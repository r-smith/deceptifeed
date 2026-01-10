package certutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// GenerateSelfSigned creates a self-signed certificate and returns it as a
// tls.Certificate. If certPath and keyPath are provided, the generated
// certificate and private key are saved to disk.
func GenerateSelfSigned(certPath string, keyPath string) (tls.Certificate, error) {
	// Generate 2048-bit RSA private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Set the certificate validity period to 10 years.
	notBefore := time.Now()
	notAfter := notBefore.AddDate(10, 0, 0)

	// Generate a random certificate serial number.
	serialNumber := make([]byte, 16)
	_, err = rand.Read(serialNumber)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate certificate serial number: %w", err)
	}

	// Configure the certificate template.
	template := x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serialNumber),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create the certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	keyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}

	// Save the certificate and key to disk.
	if len(certPath) > 0 && len(keyPath) > 0 {
		// Silently ignore any potential errors and continue.
		_ = writeCertAndKey(certPEM, keyPEM, certPath, keyPath)
	}

	return tls.X509KeyPair(pem.EncodeToMemory(certPEM), pem.EncodeToMemory(keyPEM))
}

// writeCertAndKey saves the public certificate and private key in PEM format
// to the specified paths.
func writeCertAndKey(cert *pem.Block, key *pem.Block, certPath string, keyPath string) error {
	// Write the certificate.
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, cert); err != nil {
		return err
	}

	// Write the private key.
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, key); err != nil {
		return err
	}

	return nil
}
