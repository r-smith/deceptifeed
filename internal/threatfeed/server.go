package threatfeed

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/r-smith/deceptifeed/internal/certutil"
	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/console"
	"golang.org/x/net/websocket"
)

const (
	// saveInterval represents how frequently the threat feed is saved to disk.
	// The saved file ensures threat feed data persists across application
	// restarts. It is not the active threat feed.
	saveInterval = 20 * time.Second
)

var (
	// cfg contains the application configuration. This includes settings for
	// the threat feed server as well as for each individual honeypot server.
	cfg config.Config
)

// Start initializes and starts the threat feed server. The server provides a
// list of IP addresses observed interacting with the honeypot servers in
// various formats.
func Start(c *config.Config) {
	cfg = *c

	// Ensure exclude list exists.
	if err := initExcludeList(c.ThreatFeed.ExcludeListPath); err != nil {
		fmt.Fprintln(os.Stderr, "Warning: Could not initialize exclude list:", err)
	}

	// Load exclude list into memory.
	reloadExcludeList(c.ThreatFeed.ExcludeListPath)

	// Load threatfeed CSV file.
	if err := loadCSV(); err != nil {
		console.Error(console.Feed, "Failed to load threatfeed database '%s': %v", cfg.ThreatFeed.DatabasePath, err)
		return
	}
	deleteExpired()

	// Start a background goroutine to perform periodic maintenance:
	// 1. Reload the exclude list if the file changed.
	// 2. Remove expired entries from the threatfeed.
	// 3. Save the current threatfeed to disk.
	ticker := time.NewTicker(saveInterval)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			reloadExcludeList(c.ThreatFeed.ExcludeListPath)

			if dataChanged.CompareAndSwap(true, false) {
				deleteExpired()
				if err := saveCSV(); err != nil {
					console.Error(console.Feed, "Failed to save threatfeed database '%s': %v", cfg.ThreatFeed.DatabasePath, err)
				}
			}
		}
	}()

	// Monitor honeypot log data and broadcast to connected WebSocket clients.
	go broadcastLogsToClients()

	// Setup handlers and server configuration.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", enforcePrivateIP(handleNotFound))
	mux.HandleFunc("GET /{$}", enforcePrivateIP(handleHome))
	mux.HandleFunc("GET /css/style.css", enforcePrivateIP(handleCSS))
	mux.HandleFunc("GET /docs", enforcePrivateIP(handleDocs))
	mux.HandleFunc("GET /config", enforcePrivateIP(handleConfig))
	mux.HandleFunc("GET /live", enforcePrivateIP(handleLiveIndex))
	mux.Handle("GET /live-ws", websocket.Handler(handleWebSocket))
	// Threat feed handlers.
	mux.HandleFunc("GET /webfeed", enforcePrivateIP(disableCache(handleHTML)))
	mux.HandleFunc("GET /plain", enforcePrivateIP(disableCache(handlePlain)))
	mux.HandleFunc("GET /csv", enforcePrivateIP(disableCache(handleCSV)))
	mux.HandleFunc("GET /json", enforcePrivateIP(disableCache(handleJSON)))
	mux.HandleFunc("GET /stix", enforcePrivateIP(disableCache(handleSTIX)))
	// TAXII 2.1 handlers.
	mux.HandleFunc("GET    /taxii2/", enforcePrivateIP(handleNotFound))
	mux.HandleFunc("POST   /taxii2/", enforcePrivateIP(handleNotFound))
	mux.HandleFunc("DELETE /taxii2/", enforcePrivateIP(handleNotFound))
	mux.HandleFunc("GET    /taxii2/{$}", enforcePrivateIP(handleTAXIIDiscovery))
	mux.HandleFunc("GET    /taxii2/api/{$}", enforcePrivateIP(handleTAXIIRoot))
	mux.HandleFunc("GET    /taxii2/api/collections/{$}", enforcePrivateIP(handleTAXIICollections))
	mux.HandleFunc("GET    /taxii2/api/collections/{id}/{$}", enforcePrivateIP(handleTAXIICollections))
	mux.HandleFunc("GET    /taxii2/api/collections/{id}/objects/{$}", enforcePrivateIP(disableCache(handleTAXIIObjects)))
	// Honeypot log handlers.
	mux.HandleFunc("GET /logs", enforcePrivateIP(handleLogsMain))
	mux.HandleFunc("GET /logs/{logtype}", enforcePrivateIP(handleLogs))
	mux.HandleFunc("GET /logs/{logtype}/{subtype}", enforcePrivateIP(handleLogs))

	srv := &http.Server{
		Addr:         ":" + c.ThreatFeed.Port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  0,
	}

	// If TLS is disabled, start the threatfeed over HTTP.
	if !c.ThreatFeed.EnableTLS {
		l, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			console.Error(console.Feed, "Failed to start threatfeed on port %s: %v", c.ThreatFeed.Port, err)
			return
		}
		console.Info(console.Feed, "Threatfeed is active and listening on port %s (http://%s:%s)", c.ThreatFeed.Port, config.GetHostIP(), c.ThreatFeed.Port)
		if err := srv.Serve(l); err != nil {
			console.Error(console.Feed, "Threatfeed stopped on port %s: %v", c.ThreatFeed.Port, err)
		}
		return
	}

	// Generate a self-signed cert if the provided key and cert aren't found.
	if _, err := os.Stat(c.ThreatFeed.CertPath); errors.Is(err, fs.ErrNotExist) {
		if _, err := os.Stat(c.ThreatFeed.KeyPath); errors.Is(err, fs.ErrNotExist) {
			cert, err := certutil.GenerateSelfSigned(c.ThreatFeed.CertPath, c.ThreatFeed.KeyPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to generate threat feed TLS certificate:", err)
				return
			}

			// Add cert to server config.
			srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		}
	}

	// Start the threatfeed over HTTPS.
	l, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		console.Error(console.Feed, "Failed to start threatfeed on port %s: %v", c.ThreatFeed.Port, err)
		return
	}

	console.Info(console.Feed, "Threatfeed is active and listening on port %s (https://%s:%s)", c.ThreatFeed.Port, config.GetHostIP(), c.ThreatFeed.Port)
	if err := srv.ServeTLS(l, "", ""); err != nil {
		console.Error(console.Feed, "Threatfeed stopped on port %s: %v", c.ThreatFeed.Port, err)
		return
	}
}
