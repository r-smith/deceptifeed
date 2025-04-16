package threatfeed

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"time"

	"github.com/r-smith/deceptifeed/internal/certutil"
	"github.com/r-smith/deceptifeed/internal/config"
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

	// Check for and open an existing threat feed CSV file, if available.
	if err := loadCSV(); err != nil {
		fmt.Fprintln(os.Stderr, "The Threat Feed server has stopped: Failed to open Threat Feed data:", err)
		return
	}
	deleteExpired()

	// Periodically delete expired entries and save the current threat feed to
	// disk.
	ticker := time.NewTicker(saveInterval)
	go func() {
		for range ticker.C {
			if dataChanged {
				dataChanged = false
				deleteExpired()
				if err := saveCSV(); err != nil {
					fmt.Fprintln(os.Stderr, "Error saving Threat Feed data:", err)
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

	// Start the threat feed (HTTP) server if TLS is not enabled.
	if !c.ThreatFeed.EnableTLS {
		fmt.Printf("Starting threat feed (HTTP) on port: %s\n", c.ThreatFeed.Port)
		if err := srv.ListenAndServe(); err != nil {
			fmt.Fprintln(os.Stderr, "The threat feed server has stopped:", err)
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

	// Start the threat feed (HTTPS) server.
	fmt.Printf("Starting threat feed (HTTPS) on port: %s\n", c.ThreatFeed.Port)
	if err := srv.ListenAndServeTLS(c.ThreatFeed.CertPath, c.ThreatFeed.KeyPath); err != nil {
		fmt.Fprintln(os.Stderr, "The threat feed server has stopped:", err)
	}
}
