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
	"github.com/r-smith/deceptifeed/internal/eventdata"
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
func determineConfig(srv *config.Server) *responseConfig {
	if srv.HomePagePath == "" {
		return &responseConfig{mode: modeDefault}
	}

	info, err := os.Stat(srv.HomePagePath)
	if err != nil {
		return &responseConfig{mode: modeDefault}
	}

	if info.IsDir() {
		root, err := os.OpenRoot(srv.HomePagePath)
		if err != nil {
			return &responseConfig{mode: modeDefault}
		}
		return &responseConfig{
			mode:      modeDirectory,
			fsRoot:    root,
			fsHandler: withCustomError(http.FileServerFS(noDirectoryFS{root.FS()}), srv.ErrorPagePath),
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
func Start(srv *config.Server) {
	response := determineConfig(srv)
	if response.mode == modeDirectory {
		defer response.fsRoot.Close()
	}

	switch srv.Type {
	case config.HTTP:
		listenHTTP(srv, response)
	case config.HTTPS:
		listenHTTPS(srv, response)
	}
}

// listenHTTP initializes and starts an HTTP (plaintext) honeypot server.
func listenHTTP(srv *config.Server, response *responseConfig) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleConnection(srv, parseCustomHeaders(srv.Headers), response))
	s := &http.Server{
		Addr:         ":" + srv.Port,
		Handler:      mux,
		ErrorLog:     log.New(io.Discard, "", log.LstdFlags),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  0,
	}

	// Start the HTTP server.
	fmt.Printf("Starting HTTP server on port: %s\n", srv.Port)
	if err := s.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "The HTTP server on port %s has stopped: %v\n", srv.Port, err)
	}
}

// listenHTTPS initializes and starts an HTTPS (encrypted) honeypot server.
func listenHTTPS(srv *config.Server, response *responseConfig) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleConnection(srv, parseCustomHeaders(srv.Headers), response))
	s := &http.Server{
		Addr:         ":" + srv.Port,
		Handler:      mux,
		ErrorLog:     log.New(io.Discard, "", log.LstdFlags),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  0,
	}

	// If the cert and key aren't found, generate a self-signed certificate.
	if _, err := os.Stat(srv.CertPath); errors.Is(err, fs.ErrNotExist) {
		if _, err := os.Stat(srv.KeyPath); errors.Is(err, fs.ErrNotExist) {
			cert, err := certutil.GenerateSelfSigned(srv.CertPath, srv.KeyPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to generate HTTPS certificate:", err)
				return
			}

			// Add cert to server config.
			s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		}
	}

	// Start the HTTPS server.
	fmt.Printf("Starting HTTPS server on port: %s\n", srv.Port)
	if err := s.ListenAndServeTLS(srv.CertPath, srv.KeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "The HTTPS server on port %s has stopped: %v\n", srv.Port, err)
	}
}

// handleConnection processes incoming HTTP and HTTPS client requests. It logs
// the details of each request, updates the threat feed, and serves responses
// based on the honeypot configuration.
func handleConnection(srv *config.Server, customHeaders map[string]string, response *responseConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Record connection details.
		evt := eventdata.Connection{}
		evt.ServerIP, evt.ServerPort = getLocalAddr(r)
		evt.SourceIP, _, _ = net.SplitHostPort(r.RemoteAddr)

		// If configured to use a proxy header, extract the client IP and
		// record proxy information.
		if srv.SourceIPHeader != "" {
			// If the header is missing, invalid, contains multiple IPs, or if
			// there a multiple headers with the same name, parsing will fail,
			// and SourceIP will contain the IP that connected to the honeypot.
			evt.ProxyIP = evt.SourceIP
			header := r.Header[srv.SourceIPHeader]
			switch len(header) {
			case 0:
				evt.ProxyError = "missing header " + srv.SourceIPHeader
			case 1:
				v := header[0]
				if _, err := netip.ParseAddr(v); err != nil {
					if strings.Contains(v, ",") {
						evt.ProxyError = "multiple values in header " + srv.SourceIPHeader
					} else {
						evt.ProxyError = "invalid IP in header " + srv.SourceIPHeader
					}
				} else {
					evt.ProxyParsed = true
					evt.SourceIP = v
				}
			default:
				evt.ProxyError = "multiple instances of header " + srv.SourceIPHeader
			}
		}

		logData := prepareLog(&evt, srv)

		// Record the HTTP request information.
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
		// record the credentials.
		if username, password, ok := r.BasicAuth(); ok {
			eventDetails = append(eventDetails,
				slog.Group("basic_auth",
					slog.String("username", username),
					slog.String("password", password),
				),
			)
		}

		// Log the event and update the threat feed.
		logData = append(logData, slog.Group("event_details", eventDetails...))
		srv.Logger.LogAttrs(context.Background(), slog.LevelInfo, "http", logData...)

		fmt.Printf("[HTTP] %s %s %s %s\n", evt.SourceIP, r.Method, r.URL.Path, r.URL.RawQuery)

		if shouldUpdateThreatFeed(srv, r) {
			threatfeed.Update(evt.SourceIP)
		}

		// Add any configured headers to the HTTP response.
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
				serveErrorPage(w, r, srv.ErrorPagePath)
			}
		case modeFile:
			// Serve a single file.
			if r.URL.Path == "/" || r.URL.Path == "/index.html" {
				http.ServeFile(w, r, srv.HomePagePath)
			} else {
				serveErrorPage(w, r, srv.ErrorPagePath)
			}
		case modeDirectory:
			// Serve files from a directory.
			response.fsHandler.ServeHTTP(w, r)
		}
	}
}

// preparelog builds structured log fields from network connection metadata.
func prepareLog(evt *eventdata.Connection, srv *config.Server) []slog.Attr {
	d := make([]slog.Attr, 0, 8)
	d = append(d,
		slog.String("source_ip", evt.SourceIP),
	)
	if srv.UseProxyProtocol {
		d = append(d,
			slog.Bool("source_ip_parsed", evt.ProxyParsed),
			slog.String("source_ip_error", evt.ProxyError),
			slog.String("proxy_ip", evt.ProxyIP),
		)
	}
	d = append(d,
		slog.String("server_ip", evt.ServerIP),
		slog.String("server_port", evt.ServerPort),
		slog.String("server_name", config.Hostname),
	)
	return d
}

// serveErrorPage serves an error HTTP response code and optional html page.
func serveErrorPage(w http.ResponseWriter, r *http.Request, path string) {
	if path == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	http.ServeFile(w, r, path)
}

// shouldUpdateThreatFeed determines if the threat feed should be updated based
// on the server's configured rules.
func shouldUpdateThreatFeed(srv *config.Server, r *http.Request) bool {
	// Return false if `sendToThreatFeed`` is disabled, or if the request
	// matches an `exclude` rule.
	if !srv.SendToThreatFeed || checkRuleMatches(srv.Rules.Exclude, r) {
		return false
	}

	// Return true if no `include` rules are defined. Otherwise, return whether
	// the request matches any of the `include` rules.
	return len(srv.Rules.Include) == 0 || checkRuleMatches(srv.Rules.Include, r)
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
