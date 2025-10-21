package token

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity/cache"
	"software.sslmate.com/src/go-pkcs12"
	"k8s.io/klog/v2"
)

type ClientCertificateCredential struct {
	cred *azidentity.ClientCertificateCredential
}

var _ CredentialProvider = (*ClientCertificateCredential)(nil)

func newClientCertificateCredential(opts *Options) (CredentialProvider, error) {
	if opts.ClientID == "" {
		return nil, fmt.Errorf("client ID cannot be empty")
	}
	if opts.TenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}
	if opts.ClientCert == "" {
		return nil, fmt.Errorf("client certificate cannot be empty")
	}
	var (
		c   azidentity.Cache
		err error
	)
	if opts.UsePersistentCache {
		c, err = cache.New(nil)
		if err != nil {
			klog.V(5).Infof("failed to create cache: %v", err)
		}
	}

	// Get the certificate and private key from file
	cert, rsaPrivateKey, err := readCertificate(opts.ClientCert, opts.ClientCertPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	azOpts := &azidentity.ClientCertificateCredentialOptions{
		ClientOptions:            azcore.ClientOptions{Cloud: opts.GetCloudConfiguration()},
		Cache:                    c,
		SendCertificateChain:     true,
		DisableInstanceDiscovery: opts.DisableInstanceDiscovery,
	}

	if opts.httpClient != nil {
		azOpts.Transport = opts.httpClient
	}

	cred, err := azidentity.NewClientCertificateCredential(
		opts.TenantID, opts.ClientID,
		[]*x509.Certificate{cert}, rsaPrivateKey,
		azOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate credential: %w", err)
	}
	return &ClientCertificateCredential{cred: cred}, nil
}

func (c *ClientCertificateCredential) Name() string {
	return "ClientCertificateCredential"
}

func (c *ClientCertificateCredential) Authenticate(ctx context.Context, opts *policy.TokenRequestOptions) (azidentity.AuthenticationRecord, error) {
	return azidentity.AuthenticationRecord{}, errAuthenticateNotSupported
}

func (c *ClientCertificateCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return c.cred.GetToken(ctx, opts)
}

func (c *ClientCertificateCredential) NeedAuthenticate() bool {
	return false
}

func decodePkcs12(pkcs []byte, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, cert, certChain, err := pkcs12.DecodeChain(pkcs, password)
	if err != nil {
		return nil, nil, err
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("expected rsa private key, got: %T", privateKey)
	}

	// DecodeChain assumes the fist certificate is the one corresponding to the publicKey.
	// Maintain backwards compatability by checking all certs for the one that matches
	// the RSA Private Key.
	for _, c := range append([]*x509.Certificate{cert}, certChain...) {
		if rsaPrivateKey.PublicKey.Equal(c.PublicKey) {
			return c, rsaPrivateKey, nil
		}
	}

	return nil, nil, fmt.Errorf("unable to find a matching public certificate")
}

func readCertificate(certFile, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	if strings.HasSuffix(certFile, ".pfx") {
		cert, err := os.ReadFile(certFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read the certificate file (%s): %w", certFile, err)
		}
		return decodePkcs12(cert, password)
	} else {
		cert, err := os.ReadFile(certFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read the certificate file (%s): %w", certFile, err)
		}
		return parseKeyPairFromPEMBlock(cert)
	}
}
