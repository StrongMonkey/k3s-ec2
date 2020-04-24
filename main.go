//go:generate go run main.go
//go:generate rm -rf client-admin.crt client-admin.key client-ca.crt client-ca.key server-ca.crt server-ca.key
package main

import (
	"crypto"
	cryptorand "crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"text/template"
	"time"

	certutil "github.com/rancher/dynamiclistener/cert"
)

var (
	kubeconfigTemplate = template.Must(template.New("kubeconfig").Parse(`apiVersion: v1
clusters:
- cluster:
    server: {{.URL}}
    certificate-authority-data: {{.CACert}}
  name: local
contexts:
- context:
    cluster: local
    namespace: default
    user: user
  name: Default
current-context: Default
kind: Config
preferences: {}
users:
- name: user
  user:
    client-certificate-data: {{.ClientCert}}
    client-key-data: {{.ClientKey}}
`))
)

func main() {
	clientCrt, clientKey := generateCert("client-ca.crt", "client-ca.key")
	caCrt, caKey := generateCert("server-ca.crt", "server-ca.key")

	factory := getSigningCertFactory(true, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "./client-ca.crt", "./client-ca.key")
	_, err := factory("system:admin", []string{"system:masters"}, "./client-admin.crt", "./client-admin.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	clientAdminCrt, err := ioutil.ReadFile("./client-admin.crt")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	clientAdminKey, err := ioutil.ReadFile("./client-admin.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var parameters []map[string]interface{}
	parameters = append(parameters,
		map[string]interface{}{
			"ParameterKey":   "K3SToken",
			"ParameterValue": randomToken(),
		},
		map[string]interface{}{
			"ParameterKey":   "K3SAgentToken",
			"ParameterValue": randomToken(),
		},
		map[string]interface{}{
			"ParameterKey":   "K3SCACrt",
			"ParameterValue": string(caCrt),
		},
		map[string]interface{}{
			"ParameterKey":   "K3SCAKey",
			"ParameterValue": string(caKey),
		},
		map[string]interface{}{
			"ParameterKey":   "K3sClientCrt",
			"ParameterValue": string(clientCrt),
		},
		map[string]interface{}{
			"ParameterKey":   "K3SClientKey",
			"ParameterValue": string(clientKey),
		},
		map[string]interface{}{
			"ParameterKey":   "K3SClusterID",
			"ParameterValue": randomToken(),
		},
		map[string]interface{}{
			"ParameterKey":   "Arn",
			"ParameterValue": os.Getenv("AWS_IAM_ARN"),
		},
	)

	data, err := json.Marshal(parameters)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := ioutil.WriteFile("parameters.json", data, 0755); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	tData := struct {
		URL        string
		CACert     string
		ClientCert string
		ClientKey  string
	}{
		URL:        "https://server-url:6443",
		CACert:     base64.StdEncoding.EncodeToString(caCrt),
		ClientCert: base64.StdEncoding.EncodeToString(clientAdminCrt),
		ClientKey:  base64.StdEncoding.EncodeToString(clientAdminKey),
	}
	dest, err := os.Create("./kubeconfig.yaml")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := kubeconfigTemplate.Execute(dest, tData); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func randomToken() string {
	token := make([]byte, 16, 16)
	_, err := cryptorand.Read(token)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return hex.EncodeToString(token)
}

func generateCert(certFile, certKey string) ([]byte, []byte) {
	caKeyBytes, _, err := certutil.LoadOrGenerateKeyFile(certKey, false)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	caKey, err := certutil.ParsePrivateKeyPEM(caKeyBytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cfg := certutil.Config{
		CommonName: fmt.Sprintf("%s-ca@%d", "k3s-client", time.Now().Unix()),
	}

	cert, err := certutil.NewSelfSignedCACert(cfg, caKey.(crypto.Signer))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := certutil.WriteCert(certFile, certutil.EncodeCertPEM(cert)); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return certutil.EncodeCertPEM(cert), caKeyBytes
}

type signedCertFactory = func(commonName string, organization []string, certFile, keyFile string) (bool, error)

func getSigningCertFactory(regen bool, altNames *certutil.AltNames, extKeyUsage []x509.ExtKeyUsage, caCertFile, caKeyFile string) signedCertFactory {
	return func(commonName string, organization []string, certFile, keyFile string) (bool, error) {
		return createClientCertKey(regen, commonName, organization, altNames, extKeyUsage, caCertFile, caKeyFile, certFile, keyFile)
	}
}

func createClientCertKey(regen bool, commonName string, organization []string, altNames *certutil.AltNames, extKeyUsage []x509.ExtKeyUsage, caCertFile, caKeyFile, certFile, keyFile string) (bool, error) {
	caBytes, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return false, err
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caBytes)

	// check for certificate expiration
	if !regen {
		regen = expired(certFile, pool)
	}

	if !regen {
		if exists(certFile, keyFile) {
			return false, nil
		}
	}

	caKeyBytes, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		return false, err
	}

	caKey, err := certutil.ParsePrivateKeyPEM(caKeyBytes)
	if err != nil {
		return false, err
	}

	caCert, err := certutil.ParseCertsPEM(caBytes)
	if err != nil {
		return false, err
	}

	keyBytes, _, err := certutil.LoadOrGenerateKeyFile(keyFile, regen)
	if err != nil {
		return false, err
	}

	key, err := certutil.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return false, err
	}

	cfg := certutil.Config{
		CommonName:   commonName,
		Organization: organization,
		Usages:       extKeyUsage,
	}
	if altNames != nil {
		cfg.AltNames = *altNames
	}
	cert, err := certutil.NewSignedCert(cfg, key.(crypto.Signer), caCert[0], caKey.(crypto.Signer))
	if err != nil {
		return false, err
	}

	return true, certutil.WriteCert(certFile, append(certutil.EncodeCertPEM(cert), certutil.EncodeCertPEM(caCert[0])...))
}

func exists(files ...string) bool {
	for _, file := range files {
		if _, err := os.Stat(file); err != nil {
			return false
		}
	}
	return true
}

func expired(certFile string, pool *x509.CertPool) bool {
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return false
	}
	certificates, err := certutil.ParseCertsPEM(certBytes)
	if err != nil {
		return false
	}
	_, err = certificates[0].Verify(x509.VerifyOptions{
		Roots: pool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	})
	if err != nil {
		return true
	}
	return certutil.IsCertExpired(certificates[0])
}
