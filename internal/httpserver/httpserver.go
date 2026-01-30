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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/r-smith/deceptifeed/internal/certutil"
	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/console"
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
			fsHandler: withCustomError(http.FileServerFS(noDirectoryFS{root.FS()}), srv),
		}
	}

	return &responseConfig{
		mode: modeFile,
	}
}

// Start initializes and starts an HTTP or HTTPS honeypot server. It logs all
// request details and updates the threatfeed as needed. If a filesystem path
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
	mux.HandleFunc("/", handleConnection(srv, response))
	s := &http.Server{
		Addr:              ":" + srv.Port,
		Handler:           mux,
		ErrorLog:          log.New(io.Discard, "", log.LstdFlags),
		ReadTimeout:       time.Duration(srv.SessionTimeout) * time.Second,
		WriteTimeout:      time.Duration(srv.SessionTimeout) * time.Second * 2,
		ReadHeaderTimeout: 0, // Falls back to ReadTimeout
		IdleTimeout:       0, // Falls back to ReadTimeout
	}

	// Start the HTTP listener and serve.
	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		console.Error(console.HTTP, "Failed to start honeypot on port %s: %v", srv.Port, err)
		return
	}

	console.Info(console.HTTP, "Honeypot is active and listening on port %s", srv.Port)
	if err := s.Serve(l); err != nil {
		console.Error(console.HTTP, "Honeypot stopped on port %s: %v", srv.Port, err)
		return
	}
}

// listenHTTPS initializes and starts an HTTPS (encrypted) honeypot server.
func listenHTTPS(srv *config.Server, response *responseConfig) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleConnection(srv, response))
	s := &http.Server{
		Addr:              ":" + srv.Port,
		Handler:           mux,
		ErrorLog:          log.New(io.Discard, "", log.LstdFlags),
		ReadTimeout:       time.Duration(srv.SessionTimeout) * time.Second,
		WriteTimeout:      time.Duration(srv.SessionTimeout) * time.Second * 2,
		ReadHeaderTimeout: 0, // Falls back to ReadTimeout
		IdleTimeout:       0, // Falls back to ReadTimeout
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

	// Start the HTTPS listener and serve.
	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		console.Error(console.HTTP, "Failed to start honeypot on port %s: %v", srv.Port, err)
		return
	}

	console.Info(console.HTTP, "Honeypot is active and listening on port %s", srv.Port)
	if err := s.ServeTLS(l, "", ""); err != nil {
		console.Error(console.HTTP, "Honeypot stopped on port %s: %v", srv.Port, err)
		return
	}
}

// handleConnection processes incoming HTTP and HTTPS client requests. It logs
// the details of each request, updates the threatfeed, and serves responses
// based on the honeypot configuration.
func handleConnection(srv *config.Server, response *responseConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Record connection details.
		evt := eventdata.Connection{}
		evt.ServerIP, evt.ServerPort = getLocalAddr(r)
		if addr, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
			evt.SourceIP = addr.Addr().Unmap()
		}

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
				v := strings.TrimSpace(header[0])
				if ip, err := netip.ParseAddr(v); err != nil {
					if strings.Contains(v, ",") {
						evt.ProxyError = "multiple values in header " + srv.SourceIPHeader
					} else {
						evt.ProxyError = "invalid IP in header " + srv.SourceIPHeader
					}
				} else {
					evt.ProxyParsed = true
					evt.SourceIP = ip.Unmap()
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

		// Log and report the interaction.
		if srv.LogInteractions {
			logData = append(logData, slog.Group("event_details", eventDetails...))
			srv.Logger.LogAttrs(context.Background(), slog.LevelInfo, "http", logData...)

			console.Debug(console.HTTP, "%s → %s %s %s", evt.SourceIP, r.Method, r.URL.Path, r.URL.RawQuery)
		}
		if shouldUpdateThreatFeed(srv, r) {
			threatfeed.Update(evt.SourceIP)
		}

		// Apply custom headers from the configuration to the HTTP response.
		for header, value := range srv.CustomHeaders {
			w.Header().Set(header, value)
		}

		// Serve a response based on the honeypot configuration.
		switch response.mode {
		case modeDefault:
			// Serve a 401 with the WWW-Authenticate header set. This results
			// in a login prompt when visiting in a browser.
			if r.URL.Path == "/" || r.URL.Path == "/index.html" {
				// Use direct map assignment to keep "WWW" casing.
				w.Header()["WWW-Authenticate"] = []string{"Basic"}
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				serveErrorPage(w, r, srv)
			}
		case modeFile:
			// Serve a single file.
			if r.URL.Path == "/" || r.URL.Path == "/index.html" {
				http.ServeFile(w, r, srv.HomePagePath)
			} else {
				serveErrorPage(w, r, srv)
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
		slog.Any("source_ip", evt.SourceIP),
	)
	if srv.UseProxyProtocol {
		d = append(d,
			slog.Bool("source_ip_parsed", evt.ProxyParsed),
			slog.String("source_ip_error", evt.ProxyError),
			slog.Any("proxy_ip", evt.ProxyIP),
		)
	}
	d = append(d,
		slog.Any("server_ip", evt.ServerIP),
		slog.String("server_port", strconv.FormatUint(uint64(evt.ServerPort), 10)),
		slog.String("server_name", config.Hostname),
	)
	return d
}

// serveErrorPage serves an error HTTP response code and optional html page.
func serveErrorPage(w http.ResponseWriter, r *http.Request, srv *config.Server) {
	code := srv.ErrorCode
	if code == 0 {
		code = config.DefaultHTTPErrorCode
	}

	// If the status code is set to 401, insert a basic auth header.
	if code == http.StatusUnauthorized {
		// Use direct map assignment to keep "WWW" casing.
		w.Header()["WWW-Authenticate"] = []string{"Basic"}
	}

	// If no custom HTML file is provided, just send the status code.
	if srv.ErrorPagePath == "" {
		w.WriteHeader(code)
		return
	}

	// Serve custom HTML file with content type and status code set.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	http.ServeFile(w, r, srv.ErrorPagePath)
}

// shouldUpdateThreatFeed determines if the threatfeed should be updated based
// on the server's configured rules.
func shouldUpdateThreatFeed(srv *config.Server, r *http.Request) bool {
	// Return false if `reportInteractions` is disabled, or if the request
	// matches an `exclude` rule.
	if !srv.ReportInteractions || checkRuleMatches(srv.Rules.Exclude, r) {
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
		// Note the title case. Target strings are pre-processed using
		// http.CanonicalHeaderKey during startup.
		switch rule.Target {
		case "Path":
			match = rule.Re.MatchString(r.URL.Path)
		case "Query":
			match = rule.Re.MatchString(r.URL.RawQuery)
		case "Method":
			match = rule.Re.MatchString(r.Method)
		case "Host":
			match = rule.Re.MatchString(r.Host)
		case "User-Agent":
			match = rule.Re.MatchString(r.UserAgent())
		default:
			if slices.ContainsFunc(r.Header[rule.Target], rule.Re.MatchString) {
				match = true
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

// getLocalAddr returns the local IP address and port from a given HTTP
// request.
func getLocalAddr(r *http.Request) (ip netip.Addr, port uint16) {
	localAddr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return netip.Addr{}, 0
	}

	// Parse as a TCP address.
	if addr, ok := localAddr.(*net.TCPAddr); ok {
		return addr.AddrPort().Addr().Unmap(), addr.AddrPort().Port()
	}

	// Fallback: If not TCP, use the string parser.
	if addr, err := netip.ParseAddrPort(localAddr.String()); err == nil {
		return addr.Addr().Unmap(), addr.Port()
	}

	return netip.Addr{}, 0
}
