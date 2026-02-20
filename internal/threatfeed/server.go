package threatfeed

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/r-smith/deceptifeed/internal/certutil"
	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/console"
	"golang.org/x/net/websocket"
)

// cfg contains the application configuration. This includes settings for the
// threatfeed server as well as for each individual honeypot server.
var cfg config.Config

// Start initializes and starts the threatfeed server. The server provides an
// API to retrieve IP addresses observed interacting with the honeypot servers.
func Start(c *config.Config) {
	cfg = *c

	// Initialize and load exclude list.
	if err := initExcludeList(c.ThreatFeed.ExcludeListPath); err != nil {
		console.Error(console.Feed, "Failed to initialize exclude list: %v", err)
	}
	reloadExcludeList(c.ThreatFeed.ExcludeListPath)

	// Load threatfeed database.
	if err := db.loadCSV(); err != nil {
		console.Error(console.Feed, "Failed to load threatfeed database '%s': %v", cfg.ThreatFeed.DatabasePath, err)
		return
	}
	db.deleteExpired()

	// Periodically save the database and reload the exclude list, as needed.
	const saveInterval = 20 * time.Second
	go db.runMaintenance(saveInterval)

	// Handle WebSocket clients in the web UI (/live).
	go broadcastLogsToClients()

	// Setup HTTP configuration and start the server.
	srv := &http.Server{
		Addr:         net.JoinHostPort("", strconv.Itoa(int(c.ThreatFeed.Port))),
		Handler:      newHandler(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  0,
	}
	startServer(srv, c.ThreatFeed.EnableTLS)
}

// startServer initializes the network listener and begins serving clients.
func startServer(srv *http.Server, useTLS bool) {
	// Start the listener.
	l, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		console.Error(console.Feed, "Failed to start threatfeed on port %d: %v", cfg.ThreatFeed.Port, err)
		return
	}

	// Determine protocol and setup certificates if using HTTPS.
	protocol := "http"
	if useTLS {
		protocol = "https"
		if err := configureTLS(srv); err != nil {
			console.Error(console.Feed, "Failed to start threatfeed on port %d: Cert initialization failed: %v", cfg.ThreatFeed.Port, err)
			return
		}
	}

	console.Info(
		console.Feed,
		"Threatfeed is active and listening on port %d (%s://%s:%d)",
		cfg.ThreatFeed.Port, protocol, config.GetHostIP(), cfg.ThreatFeed.Port,
	)

	// Start the server.
	var serveErr error
	if useTLS {
		serveErr = srv.ServeTLS(l, "", "")
	} else {
		serveErr = srv.Serve(l)
	}

	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		console.Error(console.Feed, "Threatfeed stopped on port %d: %v", cfg.ThreatFeed.Port, serveErr)
	}
}

// configureTLS prepares the server's TLS configuration. It attempts to load
// existing certificates from the paths in the threatfeed configuration. If
// missing, self-signed certificates are generated.
func configureTLS(srv *http.Server) error {
	// Load existing certificate and key. Generate self-signed cert if missing.
	cert, status, err := certutil.GetCertificate(cfg.ThreatFeed.CertPath, cfg.ThreatFeed.KeyPath)

	if status == certutil.Generated {
		console.Info(console.Feed, "Generated self-signed TLS certificate")
	}

	if err != nil {
		var saveError *certutil.SaveError
		if errors.As(err, &saveError) {
			// If failed to save, print a warning and continue.
			console.Warning(console.Feed, "Failed to save certificate to disk; generated cert will not persist: %v", err)
		} else {
			return err
		}
	} else if status == certutil.Generated && cfg.ThreatFeed.CertPath != "" && cfg.ThreatFeed.KeyPath != "" {
		console.Info(console.Feed, "Certificate saved to '%s'", cfg.ThreatFeed.CertPath)
		console.Info(console.Feed, "Private key saved to '%s'", cfg.ThreatFeed.KeyPath)
	}

	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	return nil
}

// newHandler constructs the primary mux for the threatfeed server. It maps URL
// patterns to their respective handlers.
func newHandler() http.Handler {
	mux := http.NewServeMux()

	// Web UI.
	mux.HandleFunc("GET /", enforcePrivateIP(handleNotFound))
	mux.HandleFunc("GET /{$}", enforcePrivateIP(handleHome))
	mux.HandleFunc("GET /css/style.css", enforcePrivateIP(handleCSS))
	mux.HandleFunc("GET /docs", enforcePrivateIP(handleDocs))
	mux.HandleFunc("GET /config", enforcePrivateIP(handleConfig))
	mux.HandleFunc("GET /live", enforcePrivateIP(handleLiveIndex))
	mux.Handle("GET /live-ws", websocket.Handler(handleWebSocket))
	// Threatfeed.
	mux.HandleFunc("GET /webfeed", enforcePrivateIP(disableCache(handleHTML)))
	mux.HandleFunc("GET /plain", enforcePrivateIP(disableCache(handlePlain)))
	mux.HandleFunc("GET /text", enforcePrivateIP(disableCache(handlePlain)))
	mux.HandleFunc("GET /csv", enforcePrivateIP(disableCache(handleCSV)))
	mux.HandleFunc("GET /json", enforcePrivateIP(disableCache(handleJSON)))
	mux.HandleFunc("GET /stix", enforcePrivateIP(disableCache(handleSTIX)))
	// TAXII.
	mux.HandleFunc("GET /taxii2/", enforcePrivateIP(handleNotFound))
	mux.HandleFunc("POST /taxii2/", enforcePrivateIP(handleNotFound))
	mux.HandleFunc("DELETE /taxii2/", enforcePrivateIP(handleNotFound))
	mux.HandleFunc("GET /taxii2/{$}", enforcePrivateIP(handleTAXIIDiscovery))
	mux.HandleFunc("GET /taxii2/api/{$}", enforcePrivateIP(handleTAXIIRoot))
	mux.HandleFunc("GET /taxii2/api/collections/{$}", enforcePrivateIP(handleTAXIICollections))
	mux.HandleFunc("GET /taxii2/api/collections/{id}/{$}", enforcePrivateIP(handleTAXIICollections))
	mux.HandleFunc("GET /taxii2/api/collections/{id}/objects/{$}", enforcePrivateIP(disableCache(handleTAXIIObjects)))
	// Web UI (Logs).
	mux.HandleFunc("GET /logs", enforcePrivateIP(handleLogsMain))
	mux.HandleFunc("GET /logs/{logtype}", enforcePrivateIP(handleLogs))
	mux.HandleFunc("GET /logs/{logtype}/{subtype}", enforcePrivateIP(handleLogs))

	return mux
}
