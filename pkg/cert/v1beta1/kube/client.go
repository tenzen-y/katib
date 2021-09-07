package kube

import (
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"strconv"
)

type Client struct {
	kubeClient kubernetes.Interface
	dynamicClient dynamic.Interface
	kubeDiscovery discovery.DiscoveryInterface
}

func (c *Client) getKubeClient() (kubernetes.Interface, dynamic.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, err
	}
	if c.kubeClient == nil {
		c.kubeClient, err = kubernetes.NewForConfig(config)
		if err != nil {
			return nil, nil, err
		}
	}
	if c.dynamicClient == nil {
		c.dynamicClient, err = dynamic.NewForConfig(config)
		if err != nil {
			return nil, nil, err
		}
	}
	if c.kubeDiscovery == nil {
		c.kubeDiscovery = c.kubeClient.Discovery()
	}
	return c.kubeClient, c.dynamicClient, nil
}

func (c *Client) GetServerVersion() (map[string]int, error){
	_, _, err := c.getKubeClient()
	if err != nil {
		return nil, err
	}
	versions, err := c.kubeDiscovery.ServerVersion()
	if err != nil {
		return nil, err
	}

	serverVersion := make(map[string]int, 2)
	serverVersion["major"], err = strconv.Atoi(versions.Major)
	if err != nil {
		return nil, err
	}
	serverVersion["minor"], err = strconv.Atoi(versions.Minor)
	return serverVersion, err
}

func (c *Client) GetCSRAPIVersion() (string, error) {
	_, _, err := c.getKubeClient()
	if err != nil {
		return "", err
	}
	serverVersion, err := c.GetServerVersion()
	if err != nil {
		return "", err
	}

	var csrAPIVersion string
	if serverVersion["major"] == 1 && serverVersion["minor"] > 18 {
		csrAPIVersion = "v1"
	} else {
		csrAPIVersion = "v1beta1"
	}
	return csrAPIVersion, nil
}

func (c *Client) GetCSRClient() (dynamic.NamespaceableResourceInterface, error) {
	_, dynamicClient, err := c.getKubeClient()
	if err != nil {
		return nil, err
	}
	csrAPIVersion, err := c.GetCSRAPIVersion()
	if err != nil {
		return nil, err
	}

	var csrGVR schema.GroupVersionResource
	switch csrAPIVersion {
	case "v1":
		csrGVR = schema.GroupVersionResource{
			Group: "certificates.k8s.io",
			Version: "v1",
			Resource: "certificatesigningrequests",
		}
	case "v1beta1":
		csrGVR = schema.GroupVersionResource{
			Group: "certificates.k8s.io",
			Version: "v1beta1",
			Resource: "certificatesigningrequests",
		}
	}
	return dynamicClient.Resource(csrGVR), nil
}

func (c *Client) GenerateCSRResource() {
	_, dynamicClient, err := c.getKubeClient()
	if err != nil {
		return nil, err
	}
	csrAPIVersion, err := c.GetCSRAPIVersion()
	if err != nil {
		return nil, err
	}

	var kubeCSR unstructured.Unstructured
	switch csrAPIVersion {
	case "v1":
	case "v1beta1":

	}
	kubeCSR := &certificatesv1.CertificateSigningRequest{
		TypeMeta: metav1.TypeMeta{
			Kind: "CertificateSigningRequest",
			APIVersion: "certificates.k8s.io/v1",
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

}
