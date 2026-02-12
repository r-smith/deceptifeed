package certutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"time"
)

// SaveError indicates that a certificate was successfully generated and is
// ready for use in memory, but could not be saved to disk.
type SaveError struct {
	// Err is the underlying file system error that occurred during saving.
	Err error
}

func (e *SaveError) Error() string {
	return e.Err.Error()
}

func (e *SaveError) Unwrap() error {
	return e.Err
}

// LoadResult indicates whether the key or public/private key pair was newly
// created or loaded from disk.
type LoadResult int

const (
	// Generated indicates a new key or public/private key pair was generated.
	Generated LoadResult = iota
	// Loaded indicates an existing key or public/private key pair was loaded.
	Loaded
)

// GetCertificate attempts to retrieve a TLS certificate and private key. If
// both files are missing or both paths are empty, it generates a new self-
// signed certificate. Otherwise, it attempts to load from the provided paths.
func GetCertificate(certPath string, keyPath string) (tls.Certificate, LoadResult, error) {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	certMissing := certPath == "" || errors.Is(certErr, fs.ErrNotExist)
	keyMissing := keyPath == "" || errors.Is(keyErr, fs.ErrNotExist)

	if certMissing && keyMissing {
		cert, err := GenerateSelfSigned(certPath, keyPath)
		return cert, Generated, err
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	return cert, Loaded, err
}

// GenerateSelfSigned creates a self-signed certificate and private key. If
// paths are provided, it attempts to save them to disk.
func GenerateSelfSigned(certPath string, keyPath string) (tls.Certificate, error) {
	// Generate 2048-bit RSA private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("couldn't generate key: %w", err)
	}

	// Set the certificate validity period to 10 years.
	notBefore := time.Now()
	notAfter := notBefore.AddDate(10, 0, 0)

	// Generate a random 128-bit serial number.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("couldn't generate serial number: %w", err)
	}

	// Configure the certificate template.
	template := x509.Certificate{
		SerialNumber:          serialNumber,
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
		return tls.Certificate{}, fmt.Errorf("couldn't create certificate: %w", err)
	}

	certPEM := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	keyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}

	// Parse into a tls.Certificate.
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(certPEM), pem.EncodeToMemory(keyPEM))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("couldn't parse key pair: %w", err)
	}

	// Attempt to save to disk. Return the valid in-memory certificate/key and
	// a SaveError if writing fails.
	if certPath != "" && keyPath != "" {
		if saveErr := writeCertAndKey(certPEM, keyPEM, certPath, keyPath); saveErr != nil {
			return cert, &SaveError{Err: saveErr}
		}
	}

	return cert, nil
}

// GenerateEd25519Key creates a private key. If a path is provided, the key is
// saved to disk.
func GenerateEd25519Key(path string) (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate key: %w", err)
	}

	// Attempt to save to disk. Return the valid in-memory key and a SaveError
	// if writing fails.
	if path != "" {
		if err := writePrivateKey(key, path); err != nil {
			return key, &SaveError{Err: err}
		}
	}

	return key, nil
}

// writeCertAndKey saves a PEM-encoded certificate and private key to disk.
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

// writePrivateKey encodes and saves a private key to the specified path in PEM
// format.
func writePrivateKey(key any, path string) error {
	// Setup PEM block.
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	// Write PEM-encoded key to disk.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, keyPEM)
}
