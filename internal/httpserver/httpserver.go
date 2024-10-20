package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/r-smith/cti-honeypot/internal/config"
	"github.com/r-smith/cti-honeypot/internal/threatfeed"
)

// StartHTTP initializes and starts an HTTP honeypot server. This is a fully
// functional HTTP server designed to log all incoming requests for analysis.
func StartHTTP(cfg *config.Config, srv *config.Server) {
	// Get any custom headers, if provided.
	headers := parseCustomHeaders(srv.Banner)

	// Setup handler.
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleConnection(cfg, srv, headers))

	// Start the HTTP server.
	fmt.Printf("Starting HTTP server on port: %s\n", srv.Port)
	if err := http.ListenAndServe(":"+srv.Port, mux); err != nil {
		fmt.Fprintln(os.Stderr, "The HTTP server has terminated:", err)
	}
}

// StartHTTPS initializes and starts an HTTPS honeypot server. This  is a fully
// functional HTTPS server designed to log all incoming requests for analysis.
func StartHTTPS(cfg *config.Config, srv *config.Server) {
	// Get any custom headers, if provided.
	headers := parseCustomHeaders(srv.Banner)

	// Setup handler and initialize HTTPS config.
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleConnection(cfg, srv, headers))
	server := &http.Server{
		Addr:    ":" + srv.Port,
		Handler: mux,
	}

	// If the cert and key aren't found, generate a self-signed certificate.
	if _, err := os.Stat(srv.CertPath); os.IsNotExist(err) {
		if _, err := os.Stat(srv.KeyPath); os.IsNotExist(err) {
			// Generate a self-signed certificate.
			cert, err := generateSelfSignedCert(srv.CertPath, srv.KeyPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to generate HTTPS certificate:", err)
				return
			}

			// Add cert to server config.
			server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		}
	}

	// Start the HTTPS server.
	fmt.Printf("Starting HTTPS server on port: %s\n", srv.Port)
	if err := server.ListenAndServeTLS(srv.CertPath, srv.KeyPath); err != nil {
		fmt.Fprintln(os.Stderr, "The HTTPS server has terminated:", err)
	}
}

// handleConnection is the handler for incoming HTTP and HTTPS client requests.
// It logs the details of each request and generates responses based on the
// requested URL. When the root or index.html is requested, it serves either an
// HTML file specified in the configuration or a default page prompting for
// basic HTTP authentication. Requests for any other URLs will return a 404
// error to the client.
func handleConnection(cfg *config.Config, srv *config.Server, customHeaders map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Log details of the incoming HTTP request.
		dst_ip, dst_port := getLocalAddr(r)
		src_ip, src_port, _ := net.SplitHostPort(r.RemoteAddr)
		username, password := decodeBasicAuthCredentials(r.Header.Get("Authorization"))
		cfg.Logger.LogAttrs(context.Background(), slog.LevelInfo, "",
			slog.String("event_type", "http"),
			slog.String("source_ip", src_ip),
			slog.String("source_port", src_port),
			slog.String("sensor_ip", dst_ip),
			slog.String("sensor_port", dst_port),
			slog.String("sensor_name", config.GetHostname()),
			slog.Group("event_details",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("query", r.URL.RawQuery),
				slog.String("user_agent", r.UserAgent()),
				slog.String("protocol", r.Proto),
				slog.String("host", r.Host),
				slog.String("basic_auth_username", username),
				slog.String("basic_auth_password", password),
				slog.Any("request_headers", flattenHeaders(r.Header)),
			),
		)

		// Print a simplified version of the request to the console.
		fmt.Printf("[HTTP] %s %s %s %s\n", src_ip, r.Method, r.URL.Path, r.URL.RawQuery)

		// Update the threat feed with the source IP address from the request.
		threatfeed.UpdateIoC(src_ip)

		// If custom headers are provided, add each header and its value to the
		// HTTP response.
		for key, value := range customHeaders {
			w.Header().Set(key, value)
		}

		// Serve the web content to the client based on the requested URL. If
		// the root or /index.html is requested, serve the specified content.
		// For any other requests, return a '404 Not Found' response.
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			// The request is for the root or /index.html.
			if len(srv.HtmlPath) > 0 {
				// Serve the custom HTML file specified in the configuration.
				http.ServeFile(w, r, srv.HtmlPath)
			} else {
				// Serve the default page that prompts the client for basic
				// authentication.
				w.Header().Set("WWW-Authenticate", "Basic")
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			}
		} else {
			// The request is outside the root or /index.html. Respond with a
			// 404 error.
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		}
	}
}

// parseCustomHeaders parses a string of custom headers, if provided in the
// configuration, into a map[string]string. The keys in the map are the custom
// header names. For example, given the input:
// "Server: Microsoft-IIS/8.5, X-Powered-By: ASP.NET", the function would
// return a map with "Server" and "X-Powered-By" as keys, each linked to their
// corresponding values.
func parseCustomHeaders(headers string) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	result := make(map[string]string)
	kvPairs := strings.Split(headers, ",")
	for _, pair := range kvPairs {
		kv := strings.Split(strings.TrimSpace(pair), ":")
		if len(kv) == 2 {
			result[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return result
}

// flattenHeaders converts HTTP headers from an http.Request from the format of
// map[string][]string to map[string]string. This results in a cleaner format
// for logging, where each headers values are represented as a single string
// instead of a slice. When a header contains multiple values, they are
// combined into a single string, separated by commas.
func flattenHeaders(headers map[string][]string) map[string]string {
	newHeaders := make(map[string]string, len(headers))
	for header, values := range headers {
		if len(values) == 1 {
			newHeaders[header] = values[0]
		} else {
			newHeaders[header] = "[" + strings.Join(values, ", ") + "]"
		}
	}
	// Delete the User-Agent header, as it is managed separately.
	delete(newHeaders, "User-Agent")
	return newHeaders
}

// decodeBasicAuthCredentials takes an HTTP "Authorization" header string,
// decodes it, and extracts the username and password. The Basic Authentication
// header follows the format 'username:password' and is encoded in base64.
// After decoding, the username and password is returned.
func decodeBasicAuthCredentials(header string) (username string, password string) {
	if !strings.HasPrefix(header, "Basic ") {
		return "", ""
	}

	encodedCredentials := strings.TrimPrefix(header, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encodedCredentials)
	if err != nil {
		return "", ""
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", ""
	}

	return parts[0], parts[1]
}

// getLocalAddr retrieves the local IP address and port from the given HTTP
// request. If the local address is not found, it returns empty strings.
func getLocalAddr(r *http.Request) (ip string, port string) {
	localAddr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return "", ""
	} else {
		ip, port, _ = net.SplitHostPort(localAddr.String())
	}
	return ip, port
}

// generateSelfSignedCert creates a self-signed TLS certificate and private key
// and returns the resulting tls.Certificate. If file paths are provided, the
// certificate and key are also saved to disk.
func generateSelfSignedCert(certPath string, keyPath string) (tls.Certificate, error) {
	// Generate 2048-bit RSA private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Set the certificate validity period to 10 years.
	notBefore := time.Now()
	notAfter := notBefore.AddDate(10, 0, 0)

	// Generate a random serial number for the certificate.
	serialNumber := make([]byte, 16)
	_, err = rand.Read(serialNumber)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate certificate serial number: %w", err)
	}

	// Set up the template for creating the certificate.
	template := x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serialNumber),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// Use the template to create a self-signed X.509 certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	keyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}

	// Save the certificate and key to disk.
	if len(certPath) > 0 && len(keyPath) > 0 {
		_ = writeCertAndKey(certPEM, keyPEM, certPath, keyPath)
		// If saving fails, ignore the errors and use the in-memory
		// certificate.
	}

	// Parse the public certificate and private key bytes into a tls.Certificate.
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(certPEM), pem.EncodeToMemory(keyPEM))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load certificate and private key: %w", err)
	}

	// Return the tls.Certificate.
	return cert, nil
}

// writeCertAndKey saves the public certificate and private key in PEM format
// to the specified file paths.
func writeCertAndKey(cert *pem.Block, key *pem.Block, certPath string, keyPath string) error {
	// Save the certificate file to disk.
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, cert); err != nil {
		return err
	}

	// Save the private key file to disk.
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, key); err != nil {
		return err
	}

	return nil
}
