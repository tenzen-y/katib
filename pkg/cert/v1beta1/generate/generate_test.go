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
	"context"
	admissionregistration "k8s.io/api/admissionregistration/v1"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"os"
	"testing"
)

type testCase struct {
	testName string
	kubeClient kubernetes.Interface
	serverVersion *version.Info
	namespace string
	wantError bool
}

func TestGenerate(t *testing.T) {

	const testNamespace = "test"
	generatorJob := &batchv1.Job{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "batch/v1",
			Kind: "Job",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "katib-cert-generator",
			Namespace: testNamespace,
			UID: "testUID",
		},
	}
	testValidatingWebhookConfiguration := &admissionregistration.ValidatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind: "ValidatingWebhookConfiguration",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "katib.kubeflow.org",
		},
		Webhooks: []admissionregistration.ValidatingWebhook{
			{
				Name: "validator.experiment.katib.kubeflow.org",
				ClientConfig: admissionregistration.WebhookClientConfig{
					CABundle: []byte("CG=="),
				},
			},
		},
	}
	testMutatingWebhookConfiguration := &admissionregistration.MutatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind: "MutatingWebhookConfiguration",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "katib.kubeflow.org",
		},
		Webhooks: []admissionregistration.MutatingWebhook{
			{
				Name: "defaulter.experiment.katib.kubeflow.org",
				ClientConfig: admissionregistration.WebhookClientConfig{
					CABundle: []byte("Cg=="),
				},
			},
			{
				Name: "mutator.pod.katib.kubeflow.org",
				ClientConfig: admissionregistration.WebhookClientConfig{
					CABundle: []byte("Cg=="),
				},
			},
		},
	}

	tests := []testCase{
		{
			testName: "K8s1.17",
			kubeClient: fake.NewSimpleClientset(
				generatorJob,
				testValidatingWebhookConfiguration,
				testMutatingWebhookConfiguration,
			),
			serverVersion: &version.Info{Major: "1", Minor: "17"},
			namespace:  testNamespace,
			wantError: false,
		},
		{
			testName: "K8s1.18",
			kubeClient: fake.NewSimpleClientset(
				generatorJob,
				testValidatingWebhookConfiguration,
				testMutatingWebhookConfiguration,
			),
			serverVersion: &version.Info{Major: "1", Minor: "18"},
			namespace:  testNamespace,
			wantError: false,
		},
		{
			testName: "K8s1.22",
			kubeClient: fake.NewSimpleClientset(
				generatorJob,
				testValidatingWebhookConfiguration,
				testMutatingWebhookConfiguration,
			),
			serverVersion: &version.Info{Major: "1", Minor: "22"},
			namespace:  testNamespace,
			wantError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			ctx := context.TODO()
			if err := executeGenerateCommand(ctx, test); (err != nil) != test.wantError {
				t.Errorf("expected error, got '%v'", err)
			}
		})
	}

}

func executeGenerateCommand(ctx context.Context, t testCase) error {
	o := &generateOptions{
		namespace: t.namespace,
		caBundleDir: "testdata/ca.crt",
		kubeClient: t.kubeClient,
	}

	discovery := o.kubeClient.Discovery().(*fakediscovery.FakeDiscovery)
	discovery.FakedServerVersion = t.serverVersion
	certs, err := o.requestServerCert(ctx, discovery)
	if err = o.injectTestServerCert(ctx); err != nil {
		return err
	}
	if err != nil {
		return err
	}
	return o.injectCert(ctx, certs)
}

// inject serverCert to CSR
func (o *generateOptions) injectTestServerCert (ctx context.Context) error {
	serverCert, err := os.ReadFile("testdata/server-cert.pem")
	if err != nil {
		return err
	}
	switch o.csrAPIVersion {
	case "v1":
		kubeCSRv1, err := o.kubeClient.CertificatesV1().CertificateSigningRequests().Get(ctx, o.csrName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		kubeCSRv1.Status.Certificate = serverCert
		if _, err = o.kubeClient.CertificatesV1().CertificateSigningRequests().UpdateStatus(ctx, kubeCSRv1, metav1.UpdateOptions{}); err != nil {
			return err
		}
	case "v1beta1":
		kubeCSRv1beta1, err := o.kubeClient.CertificatesV1beta1().CertificateSigningRequests().Get(ctx, o.csrName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		kubeCSRv1beta1.Status.Certificate = serverCert
		if _, err = o.kubeClient.CertificatesV1beta1().CertificateSigningRequests().UpdateStatus(ctx, kubeCSRv1beta1, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}
	return nil
}