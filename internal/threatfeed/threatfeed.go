package threatfeed

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/r-smith/cti-honeypot/internal/config"
)

// StartThreatFeed initializes and starts the threat feed server. The server
// provides a list of IP addresses observed interacting with the honeypot
// servers. The data is served in a format compatible with most enterprise
// firewalls.
func StartThreatFeed(threatFeed *config.ThreatFeed) {
	// Check for and open an existing threat feed JSON database, if available.
	err := loadIoC(threatFeed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "The Threat Feed server has terminated: Failed to open Threat Feed database:", err)
		return
	}

	// Setup handlers.
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleConnection)
	mux.HandleFunc("/empty/", serveEmpty)

	// Start the threat feed HTTP server.
	fmt.Printf("Starting Threat Feed server on port: %s\n", threatFeed.Port)
	if err := http.ListenAndServe(":"+threatFeed.Port, mux); err != nil {
		fmt.Fprintln(os.Stderr, "The Threat Feed server has terminated:", err)
	}
}

// handleConnection processes incoming HTTP requests for the threat feed
// server. It serves the sorted list of IP addresses observed interacting with
// the honeypot servers.
func handleConnection(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()

	// Calculate expiry time.
	now := time.Now()
	expiryTime := now.Add(-time.Hour * time.Duration(expiryHours))

	// If the IP is not expired, convert it to a string for sorting.
	var netIPs []net.IP
	for ip, ioc := range iocMap {
		if ioc.LastSeen.After(expiryTime) {
			netIPs = append(netIPs, net.ParseIP(ip))
		}
	}

	// Sort the IP addresses.
	sort.Slice(netIPs, func(i, j int) bool {
		return bytes.Compare(netIPs[i], netIPs[j]) < 0
	})

	// Serve the sorted list of IP addresses.
	w.Header().Set("Content-Type", "text/plain")
	for _, ip := range netIPs {
		if ip == nil {
			// Skip IP addresses that failed parsing.
			continue
		}
		_, err := w.Write([]byte(ip.String() + "\n"))
		if err != nil {
			http.Error(w, "Falled to write response", http.StatusInternalServerError)
			return
		}
	}
}

// serveEmpty handles HTTP requests to /empty/. It returns an empty body with
// status code 200. This endpoint is useful for clearing the threat feed in
// firewalls, as many firewalls retain the last ingested feed. Firewalls can be
// configured to point to this endpoint, effectively clearing all previous
// threat feed data.
func serveEmpty(w http.ResponseWriter, r *http.Request) {
	// Serve an empty body with status code 200.
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
}
