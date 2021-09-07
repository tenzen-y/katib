/*
Copyright 2021 The Kubeflow Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package generate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/kubeflow/katib/pkg/cert/v1beta1/common"
	"github.com/kubeflow/katib/pkg/cert/v1beta1/kube"
	"github.com/spf13/cobra"
	certificatesv1 "k8s.io/api/certificates/v1"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	"k8s.io/utils/pointer"
	"os"
	"path"
	"strings"
	"time"
)

type generateOptions struct {
	namespace string
	fullServiceDomain string
	csrName string
	caBundleDir string
}

func NewGenerateCmd(client *kube.Client) *cobra.Command {
	o := &generateOptions{
		caBundleDir: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
	}
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "generate server cert for webhook",
		Long: "generate server cert for webhook",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error{
			ctx := context.TODO()
			if err := o.run(ctx, client); err != nil {
				return err
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.namespace, "namespace", "n", "kubeflow", "set namespace")
	return cmd
}

type keyPair struct {
	cert []byte
	key []byte
}
func (o *generateOptions) run (ctx context.Context, client *kube.Client) error {
	certs, err := o.requestServerCert(ctx, client)
	if err != nil {
		return err
	}
	return o.injectCert(ctx, certs)
}

func (o *generateOptions) requestServerCert (ctx context.Context, client *kube.Client) (*keyPair, error) {
	o.fullServiceDomain = strings.Join([]string{common.Service, o.namespace, "svc"}, ".")
	o.csrName = strings.Join([]string{common.Service, o.namespace}, ".")
	certs, err := o.createCSR()
	if err != nil {
		return nil, err
	}
	return certs, o.createKubeCSR(ctx, certs, versions)
}

func (o *generateOptions) injectCert(ctx context.Context, certs *keyPair) error {
	if err := o.getServerCert(ctx, certs); err != nil {
		return err
	}
	if err := o.createWebhookCertSecret(ctx, certs); err != nil {
		return err
	}
	return o.patchWebhookConfiguration(ctx)
}

// createCSR will return x509 CertificateRequest and private key
func (o *generateOptions) createCSR() (*keyPair, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: strings.Join([]string{
				"system",
				"node",
				o.fullServiceDomain,
			}, ":"),
			Organization: []string{"system:nodes"},
		},
		DNSNames: []string{
			common.Service,
			o.csrName,
			o.fullServiceDomain,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	encodedKey := &bytes.Buffer{}
	if err := pem.Encode(encodedKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rawKey)}); err != nil {
		return nil, err
	}

	rawCert, err := x509.CreateCertificateRequest(rand.Reader, template, rawKey)
	if err != nil {
		return nil, err
	}
	encodedCert := &bytes.Buffer{}
	if err = pem.Encode(encodedCert, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: rawCert}); err != nil {
		return nil, err
	}

	return &keyPair{
		encodedCert.Bytes(),
		encodedKey.Bytes(),
	}, nil
}

// NOTE: certificates.k8s.io/v1 is not supported in Kubernetes < 1.19 and certificates.k8s.io/v1beta1 removed in 1.22.
// createCSR create certificates.k8s.io CertificateSigningRequest.
func (o *generateOptions) createKubeCSR(ctx context.Context, certs *keyPair, versions *common.ServerVersion) error {

	switch o.csrAPIVersion {
	case "v1": // certificates.k8s.io/v1

		_, err := o.kubeClient.CertificatesV1().CertificateSigningRequests().Get(ctx, o.csrName, metav1.GetOptions{})
		switch {
		case err != nil && !k8serrors.IsNotFound(err):
			return err
		case err == nil:
			klog.Warning("Previous CSR was found and removed.")
			if err = o.kubeClient.CertificatesV1().CertificateSigningRequests().Delete(ctx, o.csrName, metav1.DeleteOptions{}); err != nil {
				return err
			}
		}

		kubeCSRv1 := &certificatesv1.CertificateSigningRequest{
			TypeMeta: metav1.TypeMeta{
				Kind: "CertificateSigningRequest",
				APIVersion: path.Join("certificates.k8s.io", o.csrAPIVersion),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: o.csrName,
			},
			Spec: certificatesv1.CertificateSigningRequestSpec{
				Groups: []string{
					"system:authenticated",
				},
				Request: certs.cert,
				SignerName: "kubernetes.io/kubelet-serving",
				Usages: []certificatesv1.KeyUsage{
					"digital signature",
					"key encipherment",
					"server auth",
				},
			},
		}

		klog.Infof("Creating CSR: %s", o.csrName)
		if _, err = o.kubeClient.CertificatesV1().CertificateSigningRequests().Create(ctx, kubeCSRv1, metav1.CreateOptions{}); err != nil {
			return err
		}

		kubeCSRv1.Status.Conditions = append(kubeCSRv1.Status.Conditions,
			certificatesv1.CertificateSigningRequestCondition{
				Type:           certificatesv1.CertificateApproved,
				Status:         corev1.ConditionTrue,
				Reason:         common.ApproveReason,
				Message:        common.ApproveMessage,
				LastUpdateTime: metav1.Now(),
			},
		)
		if _, err = o.kubeClient.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, o.csrName, kubeCSRv1, metav1.UpdateOptions{}); err != nil {
			return err
		}

	case "v1beta1": // certificates.k8s.io/v1beta1
		_, err := o.kubeClient.CertificatesV1beta1().CertificateSigningRequests().Get(ctx, o.csrName, metav1.GetOptions{})
		switch {
		case err != nil && !k8serrors.IsNotFound(err):
			return err
		case err == nil:
			klog.Warning("Previous CSR was found and removed.")
			if err = o.kubeClient.CertificatesV1beta1().CertificateSigningRequests().Delete(ctx, o.csrName, metav1.DeleteOptions{}); err != nil {
				return err
			}
		}

		kubeCSRv1beta1 := &certificatesv1beta1.CertificateSigningRequest{
			TypeMeta: metav1.TypeMeta{
				Kind: "CertificateSigningRequest",
				APIVersion: path.Join("certificates.k8s.io", o.csrAPIVersion),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: o.csrName,
			},
			Spec: certificatesv1beta1.CertificateSigningRequestSpec{
				Groups: []string{
					"system:authenticated",
				},
				Request: certs.cert,
				Usages: []certificatesv1beta1.KeyUsage{
					"digital signature",
					"key encipherment",
					"server auth",
				},
			},
		}

		// signerName is not supported in Kubernetes <= 1.17
		// See: https://github.com/kubeflow/katib/issues/1500
		if versions.Major == 1 && versions.Minor >= 18 {
			kubeCSRv1beta1.Spec.SignerName = pointer.String(common.SignerName)
		}

		if _, err = o.kubeClient.CertificatesV1beta1().CertificateSigningRequests().Create(ctx, kubeCSRv1beta1, metav1.CreateOptions{}); err != nil {
			return err
		}

		kubeCSRv1beta1.Status.Conditions = append(kubeCSRv1beta1.Status.Conditions,
			certificatesv1beta1.CertificateSigningRequestCondition{
				Type:           certificatesv1beta1.CertificateApproved,
				Status:         corev1.ConditionTrue,
				Reason:         common.ApproveReason,
				Message:        common.ApproveMessage,
				LastUpdateTime: metav1.Now(),
			},
		)
		if _, err = o.kubeClient.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(ctx, kubeCSRv1beta1, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}
	return nil
}

func (o *generateOptions) getServerCert(ctx context.Context, certs *keyPair) error {
	errorMessage := fmt.Sprintf(
		"After approving csr %s, the signed certificate did not appear on the resource. Giving up after 1 minute.",
		o.csrName,
	)
	switch o.csrAPIVersion {
	case "v1": // certificates.k8s.io/v1

		createdCSRv1 := &certificatesv1.CertificateSigningRequest{}
		for i:=0; i<=20; i++ {
			var err error
			createdCSRv1, err = o.kubeClient.CertificatesV1().CertificateSigningRequests().Get(ctx, o.csrName, metav1.GetOptions{})
			if err != nil {
				return err
			}

			switch {
			case !bytes.Equal(createdCSRv1.Status.Certificate, nil):
				break
			case i == 20:
				return errors.New(errorMessage)
			default:
				time.Sleep(time.Second * 3)
			}
		}
		certs.cert = createdCSRv1.Status.Certificate

	case "v1beta1": // certificates.k8s.io/v1beta1

		createdCSRv1beta1 := &certificatesv1beta1.CertificateSigningRequest{}
		for i:=0; i<=20; i++ {
			var err error
			createdCSRv1beta1, err = o.kubeClient.CertificatesV1beta1().CertificateSigningRequests().Get(ctx, o.csrName, metav1.GetOptions{})
			if err != nil {
				return err
			}

			switch {
			case !bytes.Equal(createdCSRv1beta1.Status.Certificate, nil):
				break
			case i == 20:
				return errors.New(errorMessage)
			default:
				time.Sleep(time.Second * 3)
			}
		}
		certs.cert = createdCSRv1beta1.Status.Certificate

	}

	return nil
}

// createWebhookCertSecret create Secret embedded tls.key and tls.cert
func (o *generateOptions) createWebhookCertSecret(ctx context.Context, certs *keyPair) error {

	certGeneratorJob, err := o.kubeClient.BatchV1().Jobs(o.namespace).Get(ctx, common.JobName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	jobUID := certGeneratorJob.UID
	certSecret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind: "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.Secret,
			Namespace: o.namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "batch/v1",
					Kind:       "Job",
					Controller: pointer.BoolPtr(true),
					Name:       common.JobName,
					UID:        jobUID,
				},
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.key": certs.key,
			"tls.crt": certs.cert,
		},
	}

	_, err = o.kubeClient.CoreV1().Secrets(o.namespace).Get(ctx, common.Secret, metav1.GetOptions{})
	switch {
	case err != nil && !k8serrors.IsNotFound(err):
		return err
	case err == nil:
		klog.Warning("Previous secret was found and removed.")
		if err = o.kubeClient.CoreV1().Secrets(o.namespace).Delete(ctx, common.Secret, metav1.DeleteOptions{}); err != nil {
			return err
		}
	}

	klog.Infof("Creating Secret: %s", common.Secret)
	if _, err = o.kubeClient.CoreV1().Secrets(o.namespace).Create(ctx, certSecret, metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

type jsonPatch struct {
	Op string `json:"op"`
	Path string `json:"path"`
	Value []byte `json:"value"`
}

// patchWebhookConfiguration apply patch to ValidatingWebhookConfiguration and MutatingWebhookConfiguration
func (o *generateOptions) patchWebhookConfiguration(ctx context.Context) error {
	caBundle, err := os.ReadFile(o.caBundleDir)
	if err != nil {
		return err
	}

	validatingWebhookConfigurationPatch := []jsonPatch{
		{
			Op: "replace",
			Path: "/webhooks/0/clientConfig/caBundle",
			Value: caBundle,
		},
	}
	validatingWebhookConfigurationPatchBytes, err := json.Marshal(validatingWebhookConfigurationPatch)
	if err != nil {
		return err
	}

	mutatingWebhookConfigurationPatch := []jsonPatch{
		{
			Op: "replace",
			Path: "/webhooks/0/clientConfig/caBundle",
			Value: caBundle,
		},
		{
			Op: "replace",
			Path: "/webhooks/1/clientConfig/caBundle",
			Value: caBundle,
		},
	}
	mutatingWebhookConfigurationPatchBytes, err := json.Marshal(mutatingWebhookConfigurationPatch)
	if err != nil {
		return err
	}

	klog.Info("Trying to patch ValidatingWebhookConfiguration adding the caBundle.")
	_, err = o.kubeClient.
		AdmissionregistrationV1().
		ValidatingWebhookConfigurations().
		Patch(ctx, common.Webhook, types.JSONPatchType, validatingWebhookConfigurationPatchBytes, metav1.PatchOptions{})
	if err != nil {
		klog.Errorf("Unable to patch ValidatingWebhookConfiguration %s", common.Webhook)
		return err
	}

	klog.Info("Trying to patch MutatingWebhookConfiguration adding the caBundle.")
	_, err = o.kubeClient.
		AdmissionregistrationV1().
		MutatingWebhookConfigurations().
		Patch(ctx, common.Webhook, types.JSONPatchType, mutatingWebhookConfigurationPatchBytes, metav1.PatchOptions{})
	if err != nil {
		klog.Errorf("Unable to patch MutatingWebhookConfiguration %s", common.Webhook)
		return err
	}
	return nil
}
