package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/r-smith/deceptifeed/internal/certutil"
	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/threatfeed"
)

// responseMode represents the HTTP response behavior for the honeypot.
// Depending on the configuration, the honeypot can serve a built-in default
// response, serve a specific file, or serve files from a specified directory.
type responseMode int

const (
	modeDefault   responseMode = iota // Serve the built-in default response.
	modeFile                          // Serve a specific file.
	modeDirectory                     // Serve files from a specified directory.
)

// responseConfig defines how the honeypot serves HTTP responses. It includes
// the response mode (default, file, or directory) and, for directory mode, an
// http.FileServer and file descriptor to the directory.
type responseConfig struct {
	mode      responseMode
	fsRoot    *os.Root
	fsHandler http.Handler
}

// determineConfig reads the given configuration and returns a responseConfig,
// selecting the honeypot's response mode based on whether the HomePagePath
// setting is empty, a file, or a directory.
func determineConfig(cfg *config.Server) *responseConfig {
	if len(cfg.HomePagePath) == 0 {
		return &responseConfig{mode: modeDefault}
	}

	info, err := os.Stat(cfg.HomePagePath)
	if err != nil {
		return &responseConfig{mode: modeDefault}
	}

	if info.IsDir() {
		root, err := os.OpenRoot(cfg.HomePagePath)
		if err != nil {
			return &responseConfig{mode: modeDefault}
		}
		return &responseConfig{
			mode:      modeDirectory,
			fsRoot:    root,
			fsHandler: withCustomError(http.FileServerFS(noDirectoryFS{root.FS()}), cfg.ErrorPagePath),
		}
	}

	return &responseConfig{
		mode: modeFile,
	}
}

// Start initializes and starts an HTTP or HTTPS honeypot server. It logs all
// request details and updates the threat feed as needed. If a filesystem path
// is specified in the configuration, the honeypot serves static content from
// the path.
func Start(cfg *config.Server) {
	response := determineConfig(cfg)
	if response.mode == modeDirectory {
		defer response.fsRoot.Close()
	}

	switch cfg.Type {
	case config.HTTP:
		listenHTTP(cfg, response)
	case config.HTTPS:
		listenHTTPS(cfg, response)
	}
}

// listenHTTP initializes and starts an HTTP (plaintext) honeypot server.
func listenHTTP(cfg *config.Server, response *responseConfig) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleConnection(cfg, parseCustomHeaders(cfg.Headers), response))
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

// listenHTTPS initializes and starts an HTTPS (encrypted) honeypot server.
func listenHTTPS(cfg *config.Server, response *responseConfig) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleConnection(cfg, parseCustomHeaders(cfg.Headers), response))
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ErrorLog:     log.New(io.Discard, "", log.LstdFlags),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  0,
	}

	// If the cert and key aren't found, generate a self-signed certificate.
	if _, err := os.Stat(cfg.CertPath); errors.Is(err, fs.ErrNotExist) {
		if _, err := os.Stat(cfg.KeyPath); errors.Is(err, fs.ErrNotExist) {
			cert, err := certutil.GenerateSelfSigned(cfg.CertPath, cfg.KeyPath)
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

// handleConnection processes incoming HTTP and HTTPS client requests. It logs
// the details of each request, updates the threat feed, and serves responses
// based on the honeypot configuration.
func handleConnection(cfg *config.Server, customHeaders map[string]string, response *responseConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Log connection details. The log fields and format differ based on
		// whether a custom source IP header is configured.
		dst_ip, dst_port := getLocalAddr(r)
		src_ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		logData := []slog.Attr{}
		if len(cfg.SourceIPHeader) > 0 {
			// A custom source IP header is configured. Set rem_ip to the
			// original connecting IP and src_ip to the IP from the header. If
			// the header is missing, invalid, contains multiple IPs, or if
			// there a multiple headers with the same name, parsing will fail,
			// and src_ip will fallback to the original connecting IP.
			rem_ip := src_ip
			header := r.Header[cfg.SourceIPHeader]
			parsed := false
			errMsg := ""
			switch len(header) {
			case 0:
				errMsg = "missing header " + cfg.SourceIPHeader
			case 1:
				v := header[0]
				if _, err := netip.ParseAddr(v); err != nil {
					if strings.Contains(v, ",") {
						errMsg = "multiple values in header " + cfg.SourceIPHeader
					} else {
						errMsg = "invalid IP in header " + cfg.SourceIPHeader
					}
				} else {
					parsed = true
					src_ip = v
				}
			default:
				errMsg = "multiple instances of header " + cfg.SourceIPHeader
			}

			logData = append(logData,
				slog.String("event_type", "http"),
				slog.String("source_ip", src_ip),
				slog.Bool("source_ip_parsed", parsed),
			)
			if !parsed {
				logData = append(logData, slog.String("source_ip_error", errMsg))
			}
			logData = append(logData,
				slog.String("remote_ip", rem_ip),
				slog.String("server_ip", dst_ip),
				slog.String("server_port", dst_port),
				slog.String("server_name", config.GetHostname()),
			)
		} else {
			// No custom source IP header is configured. Log the standard
			// connection details, keeping src_ip as the remote connecting IP.
			logData = append(logData,
				slog.String("event_type", "http"),
				slog.String("source_ip", src_ip),
				slog.String("server_ip", dst_ip),
				slog.String("server_port", dst_port),
				slog.String("server_name", config.GetHostname()),
			)
		}

		// Log standard HTTP request information.
		eventDetails := []any{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("query", r.URL.RawQuery),
			slog.String("user_agent", r.UserAgent()),
			slog.String("protocol", r.Proto),
			slog.String("host", r.Host),
			slog.Any("headers", flattenHeaders(r.Header)),
		}

		// If the request includes a "basic" Authorization header, decode and
		// log the credentials.
		if username, password, ok := r.BasicAuth(); ok {
			eventDetails = append(eventDetails,
				slog.Group("basic_auth",
					slog.String("username", username),
					slog.String("password", password),
				),
			)
		}

		// Combine log data and write the final log entry.
		logData = append(logData, slog.Group("event_details", eventDetails...))
		cfg.Logger.LogAttrs(context.Background(), slog.LevelInfo, "", logData...)

		// Print a simplified version of the request to the console.
		fmt.Printf("[HTTP] %s %s %s %s\n", src_ip, r.Method, r.URL.Path, r.URL.RawQuery)

		// Update the threat feed using the source IP address (src_ip). If a
		// custom header is configured, src_ip contains the IP extracted from
		// the header. Otherwise, it contains the remote connecting IP.
		if shouldUpdateThreatFeed(cfg, r) {
			threatfeed.Update(src_ip)
		}

		// Apply optional custom HTTP response headers.
		for header, value := range customHeaders {
			w.Header().Set(header, value)
		}

		// Serve a response based on the honeypot configuration.
		switch response.mode {
		case modeDefault:
			// Built-in default response.
			if r.URL.Path == "/" || r.URL.Path == "/index.html" {
				if _, _, ok := r.BasicAuth(); ok {
					time.Sleep(2 * time.Second)
				}
				w.Header()["WWW-Authenticate"] = []string{"Basic"}
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				serveErrorPage(w, r, cfg.ErrorPagePath)
			}
		case modeFile:
			// Serve a single file.
			if r.URL.Path == "/" || r.URL.Path == "/index.html" {
				http.ServeFile(w, r, cfg.HomePagePath)
			} else {
				serveErrorPage(w, r, cfg.ErrorPagePath)
			}
		case modeDirectory:
			// Serve files from a directory.
			response.fsHandler.ServeHTTP(w, r)
		}
	}
}

// serveErrorPage serves an error HTTP response code and optional html page.
func serveErrorPage(w http.ResponseWriter, r *http.Request, path string) {
	if len(path) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	http.ServeFile(w, r, path)
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
