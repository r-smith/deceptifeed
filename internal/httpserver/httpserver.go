package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/threatfeed"
)

// Start initializes and starts an HTTP or HTTPS honeypot server. The server
// is a simple HTTP server designed to log all details from incoming requests.
// Optionally, a single static HTML file can be served as the homepage,
// otherwise, the server will return only HTTP status codes to clients.
// Interactions with the HTTP server are sent to the threat feed.
func Start(cfg *config.Server) {
	switch cfg.Type {
	case config.HTTP:
		listenHTTP(cfg)
	case config.HTTPS:
		listenHTTPS(cfg)
	}
}

// listenHTTP initializes and starts an HTTP (plaintext) honeypot server.
func listenHTTP(cfg *config.Server) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleConnection(cfg, parseCustomHeaders(cfg.Headers)))
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ErrorLog:     log.New(io.Discard, "", log.LstdFlags),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  0,
	}

	// Start the HTTP server.
	fmt.Printf("Starting HTTP server on port: %s\n", cfg.Port)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "The HTTP server on port %s has stopped: %v\n", cfg.Port, err)
	}
}

// listenHTTP initializes and starts an HTTPS (encrypted) honeypot server.
func listenHTTPS(cfg *config.Server) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleConnection(cfg, parseCustomHeaders(cfg.Headers)))
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ErrorLog:     log.New(io.Discard, "", log.LstdFlags),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  0,
	}

	// If the cert and key aren't found, generate a self-signed certificate.
	if _, err := os.Stat(cfg.CertPath); os.IsNotExist(err) {
		if _, err := os.Stat(cfg.KeyPath); os.IsNotExist(err) {
			// Generate a self-signed certificate.
			cert, err := generateSelfSignedCert(cfg.CertPath, cfg.KeyPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to generate HTTPS certificate:", err)
				return
			}

			// Add cert to server config.
			srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		}
	}

	// Start the HTTPS server.
	fmt.Printf("Starting HTTPS server on port: %s\n", cfg.Port)
	if err := srv.ListenAndServeTLS(cfg.CertPath, cfg.KeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "The HTTPS server on port %s has stopped: %v\n", cfg.Port, err)
	}
}

// handleConnection is the handler for incoming HTTP and HTTPS client requests.
// It logs the details of each request and generates responses based on the
// requested URL. When the root or index.html is requested, it serves either an
// HTML file specified in the configuration or a default page prompting for
// basic HTTP authentication. Requests for any other URLs will return a 404
// error to the client.
func handleConnection(cfg *config.Server, customHeaders map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Log details of the incoming HTTP request.
		dst_ip, dst_port := getLocalAddr(r)
		src_ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		username, password, isAuth := r.BasicAuth()
		if isAuth {
			cfg.Logger.LogAttrs(context.Background(), slog.LevelInfo, "",
				slog.String("event_type", "http"),
				slog.String("source_ip", src_ip),
				slog.String("server_ip", dst_ip),
				slog.String("server_port", dst_port),
				slog.String("server_name", config.GetHostname()),
				slog.Group("event_details",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("query", r.URL.RawQuery),
					slog.String("user_agent", r.UserAgent()),
					slog.String("protocol", r.Proto),
					slog.String("host", r.Host),
					slog.Group("basic_auth",
						slog.String("username", username),
						slog.String("password", password),
					),
					slog.Any("headers", flattenHeaders(r.Header)),
				),
			)
		} else {
			cfg.Logger.LogAttrs(context.Background(), slog.LevelInfo, "",
				slog.String("event_type", "http"),
				slog.String("source_ip", src_ip),
				slog.String("server_ip", dst_ip),
				slog.String("server_port", dst_port),
				slog.String("server_name", config.GetHostname()),
				slog.Group("event_details",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("query", r.URL.RawQuery),
					slog.String("user_agent", r.UserAgent()),
					slog.String("protocol", r.Proto),
					slog.String("host", r.Host),
					slog.Any("headers", flattenHeaders(r.Header)),
				),
			)
		}

		// Print a simplified version of the request to the console.
		fmt.Printf("[HTTP] %s %s %s %s\n", src_ip, r.Method, r.URL.Path, r.URL.RawQuery)

		// Update the threat feed with the source IP address from the request.
		// If the configuration specifies an HTTP header to be used for the
		// source IP, retrieve the header value and use it instead of the
		// connecting IP.
		if shouldUpdateThreatFeed(cfg, r) {
			src := src_ip
			if len(cfg.SourceIPHeader) > 0 {
				if header := r.Header.Get(cfg.SourceIPHeader); len(header) > 0 {
					src = header
				}
			}
			threatfeed.Update(src)
		}

		// Apply any custom HTTP response headers.
		for header, value := range customHeaders {
			w.Header().Set(header, value)
		}

		// Serve a response based on the requested URL. If the root URL or
		// /index.html is requested, serve the homepage. For all other
		// requests, serve the error page with a 404 Not Found response.
		// Optionally, a single static HTML file may be specified for both the
		// homepage and the error page. If no custom files are provided,
		// default minimal responses will be served.
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			// Serve the homepage response.
			if len(cfg.HomePagePath) > 0 {
				http.ServeFile(w, r, cfg.HomePagePath)
			} else {
				w.Header()["WWW-Authenticate"] = []string{"Basic"}
				w.WriteHeader(http.StatusUnauthorized)
			}
		} else {
			// Serve the error page response.
			w.WriteHeader(http.StatusNotFound)
			if len(cfg.ErrorPagePath) > 0 {
				http.ServeFile(w, r, cfg.ErrorPagePath)
			}
		}
	}
}

// shouldUpdateThreatFeed determines if the threat feed should be updated based
// on the server's configured rules.
func shouldUpdateThreatFeed(cfg *config.Server, r *http.Request) bool {
	// Return false if `sendToThreatFeed`` is disabled, or if the request
	// matches an `exclude` rule.
	if !cfg.SendToThreatFeed || checkRuleMatches(cfg.Rules.Exclude, r) {
		return false
	}

	// Return true if no `include` rules are defined. Otherwise, return whether
	// the request matches any of the `include` rules.
	return len(cfg.Rules.Include) == 0 || checkRuleMatches(cfg.Rules.Include, r)
}

// checkRuleMatches checks if a request matches any of the specified rules.
func checkRuleMatches(rules []config.Rule, r *http.Request) bool {
	match := false
	for _, rule := range rules {
		// Ignore errors from regexp.Compile. Regular expression patterns are
		// validated at application startup.
		rx, _ := regexp.Compile(rule.Pattern)

		switch strings.ToLower(rule.Target) {
		case "path":
			match = rx.MatchString(r.URL.Path)
		case "query":
			match = rx.MatchString(r.URL.RawQuery)
		case "method":
			match = rx.MatchString(r.Method)
		case "host":
			match = rx.MatchString(r.Host)
		case "user-agent":
			match = rx.MatchString(r.UserAgent())
		default:
			header, ok := r.Header[http.CanonicalHeaderKey(rule.Target)]
			if ok {
				for _, v := range header {
					if rx.MatchString(v) {
						match = true
						break
					}
				}
			}
		}

		if rule.Negate {
			match = !match
		}
		if match {
			return true
		}
	}
	return false
}

// parseCustomHeaders takes a slice of header strings in the format of
// "Name: Value", and returns a map of the Name-Value pairs. For example, given
// the input:
// `[]{"Server: Microsoft-IIS/8.5", "X-Powered-By: ASP.NET"}`, the function
// would return a map with "Server" and "X-Powered-By" as keys, each linked to
// their corresponding values.
func parseCustomHeaders(headers []string) map[string]string {
	result := make(map[string]string)

	for _, header := range headers {
		kv := strings.SplitN(header, ":", 2)
		if len(kv) == 2 {
			result[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return result
}

// flattenHeaders converts HTTP headers from an http.Request from the format of
// map[string][]string to map[string]string. This results in a cleaner format
// for logging, where each header's values are represented as a single string
// instead of a slice. When a header contains multiple values, they are
// combined into a single string, separated by commas. Additionally, header
// names are converted to lowercase.
func flattenHeaders(headers map[string][]string) map[string]string {
	newHeaders := make(map[string]string, len(headers))
	for header, values := range headers {
		if len(values) == 1 {
			newHeaders[strings.ToLower(header)] = values[0]
		} else {
			newHeaders[strings.ToLower(header)] = "[" + strings.Join(values, ", ") + "]"
		}
	}
	// Delete the User-Agent header, as it is managed separately.
	delete(newHeaders, "user-agent")
	return newHeaders
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

	// Limit key access to the owner only.
	_ = keyFile.Chmod(0600)

	if err := pem.Encode(keyFile, key); err != nil {
		return err
	}

	return nil
}
