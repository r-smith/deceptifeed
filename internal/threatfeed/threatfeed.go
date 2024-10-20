package threatfeed

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/r-smith/cti-honeypot/internal/config"
)

var (
	// iocMap stores the Indicator of Compromise (IoC) entries which makes up
	// the threat feed database. It is initially populated by loadIoC if an
	// existing JSON database file is provided. The map is subsequently updated
	// by UpdateIoC whenever a client interacts with a honeypot server. This
	// map is accessed and served by the threat feed HTTP server.
	iocMap = make(map[string]*IoC)

	// mutex is to ensure thread-safe access to iocMap.
	mutex sync.Mutex

	// configuration holds the global configuration for the threat feed server.
	// This variable is assigned the config.ThreatFeed value that's passed in
	// during the server's startup.
	configuration config.ThreatFeed
)

// StartThreatFeed initializes and starts the threat feed server. The server
// provides a list of IP addresses observed interacting with the honeypot
// servers. The data is served in a format compatible with most enterprise
// firewalls.
func StartThreatFeed(cfg *config.ThreatFeed) {
	// Assign the passed-in config.ThreatFeed to the global configuration
	// variable.
	configuration = *cfg

	// Check for and open an existing threat feed JSON database, if available.
	err := loadIoC()
	if err != nil {
		fmt.Fprintln(os.Stderr, "The Threat Feed server has terminated: Failed to open Threat Feed database:", err)
		return
	}

	// Setup handlers.
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleConnection)
	mux.HandleFunc("/empty/", serveEmpty)

	// Start the threat feed HTTP server.
	fmt.Printf("Starting Threat Feed server on port: %s\n", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
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
	expiryTime := now.Add(-time.Hour * time.Duration(configuration.ExpiryHours))

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
		if ip == nil || (!configuration.IsPrivateIncluded && ip.IsPrivate()) {
			// Skip IP addresses that failed parsing or are private, based on
			// the configuration.
			continue
		}
		_, err := w.Write([]byte(ip.String() + "\n"))
		if err != nil {
			http.Error(w, "Falled to write response", http.StatusInternalServerError)
			return
		}
	}

	// If a custom threat file is supplied in the configuration, append the
	// contents of the file to the HTTP response. To allow for flexibility, the
	// contents of the file are not parsed or validated.
	if len(configuration.CustomThreatsPath) > 0 {
		data, err := os.ReadFile(configuration.CustomThreatsPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to read custom threats file:", err)
			return
		}
		_, err = w.Write(data)
		if err != nil {
			http.Error(w, "Falled to write response", http.StatusInternalServerError)
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
