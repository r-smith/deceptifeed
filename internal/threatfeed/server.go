package threatfeed

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/r-smith/deceptifeed/internal/config"
)

const (
	// saveInterval represents how frequently the threat feed is saved to disk.
	// The saved file ensures threat feed data persists across application
	// restarts. It is not the active threat feed.
	saveInterval = 20 * time.Second
)

var (
	// configuration holds the configuration for the threat feed server. It is
	// assigned when the server is initializing and the configuration values
	// should not change.
	configuration config.ThreatFeed
)

// Start initializes and starts the threat feed server. The server provides a
// list of IP addresses observed interacting with the honeypot servers in
// various formats.
func Start(cfg *config.ThreatFeed) {
	configuration = *cfg

	// Check for and open an existing threat feed CSV file, if available.
	err := loadCSV()
	if err != nil {
		fmt.Fprintln(os.Stderr, "The Threat Feed server has stopped: Failed to open Threat Feed data:", err)
		return
	}

	// Periodically delete expired entries and save the current threat feed to
	// disk.
	ticker := time.NewTicker(saveInterval)
	go func() {
		for range ticker.C {
			if dataChanged {
				deleteExpired()
				if err := saveCSV(); err != nil {
					fmt.Fprintln(os.Stderr, "Error saving Threat Feed data:", err)
				}
				dataChanged = false
			}
		}
	}()

	// Setup handlers and server configuration.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", enforcePrivateIP(disableCache(handlePlain)))
	mux.HandleFunc("GET /json", enforcePrivateIP(disableCache(handleJSON)))
	mux.HandleFunc("GET /json/ips", enforcePrivateIP(disableCache(handleJSONSimple)))
	mux.HandleFunc("GET /csv", enforcePrivateIP(disableCache(handleCSV)))
	mux.HandleFunc("GET /csv/ips", enforcePrivateIP(disableCache(handleCSVSimple)))
	mux.HandleFunc("GET /empty", enforcePrivateIP(handleEmpty))
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  0,
	}

	// Start the threat feed HTTP server.
	fmt.Printf("Starting Threat Feed server on port: %s\n", cfg.Port)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "The Threat Feed server has stopped:", err)
	}
}
