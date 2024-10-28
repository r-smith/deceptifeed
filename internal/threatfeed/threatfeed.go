package threatfeed

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/r-smith/deceptifeed/internal/config"
)

var (
	// configuration holds the global configuration for the threat feed server.
	// This variable is assigned the config.ThreatFeed value that's passed in
	// during the server's startup.
	configuration config.ThreatFeed

	// iocMap stores the Indicator of Compromise (IoC) entries which makes up
	// the threat feed database. It is initially populated by loadIoC if an
	// existing CSV database file is provided. The map is subsequently updated
	// by UpdateIoC whenever a client interacts with a honeypot server. This
	// map is accessed and served by the threat feed HTTP server.
	iocMap = make(map[string]*IoC)

	// mutex is to ensure thread-safe access to iocMap.
	mutex sync.Mutex

	// ticker creates a new ticker for periodically writing the IoC map to
	// disk.
	ticker = time.NewTicker(10 * time.Second)

	// hasMapChanged indicates whether the IoC map has been modified since the
	// last time it was saved to disk.
	hasMapChanged = false
)

// StartThreatFeed initializes and starts the threat feed server. The server
// provides a list of IP addresses observed interacting with the honeypot
// servers. The data is served in a format compatible with most enterprise
// firewalls.
func StartThreatFeed(cfg *config.ThreatFeed) {
	// Assign the passed-in config.ThreatFeed to the global configuration
	// variable.
	configuration = *cfg

	// Check for and open an existing threat feed CSV database, if available.
	err := loadIoC()
	if err != nil {
		fmt.Fprintln(os.Stderr, "The Threat Feed server has terminated: Failed to open Threat Feed database:", err)
		return
	}

	// Periodically save the current iocMap to disk.
	go func() {
		for range ticker.C {
			if hasMapChanged {
				if err := saveIoC(); err != nil {
					fmt.Fprintln(os.Stderr, "Error saving Threat Feed database:", err)
				}
				hasMapChanged = false
			}
		}
	}()

	// Setup handlers.
	mux := http.NewServeMux()
	mux.HandleFunc("/", enforcePrivateIP(handleConnection))
	mux.HandleFunc("/empty/", enforcePrivateIP(serveEmpty))

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

	// Parse IPs from the iocMap to net.IP for filtering and sorting. Skip any
	// IPs that have expired or don't meet the minimum threat score.
	var netIPs []net.IP
	for ip, ioc := range iocMap {
		if ioc.LastSeen.After(expiryTime) && ioc.ThreatScore >= configuration.MinimumThreatScore {
			netIPs = append(netIPs, net.ParseIP(ip))
		}
	}

	// If an exclude list is provided, filter the original IP list.
	var filteredIPList []net.IP
	if len(configuration.ExcludeListPath) > 0 {
		ipsToRemove, err := readIPsFromFile(configuration.ExcludeListPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to read threat feed exclude list:", err)
			filteredIPList = netIPs
		} else {
			filteredIPList = filterIPs(netIPs, ipsToRemove)
		}
	} else {
		filteredIPList = netIPs
	}

	// Sort the IP addresses.
	sort.Slice(filteredIPList, func(i, j int) bool {
		return bytes.Compare(filteredIPList[i], filteredIPList[j]) < 0
	})

	// Serve the sorted list of IP addresses.
	w.Header().Set("Content-Type", "text/plain")
	for _, ip := range filteredIPList {
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

// enforcePrivateIP is a middleware that restricts access to the HTTP server
// based on the client's IP address. It allows only requests from private IP
// addresses. Any other requests are denied with a 403 Forbidden error.
func enforcePrivateIP(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Could not get IP", http.StatusInternalServerError)
			return
		}

		if !net.ParseIP(ip).IsPrivate() {
			http.Error(w, "", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// readIPsFromFile reads IP addresses and CIDR ranges from a file. Each line
// should contain an IP address or CIDR. It returns a map of the unique IPs and
// CIDR ranges found in the file.
func readIPsFromFile(filepath string) (map[string]struct{}, error) {
	ips := make(map[string]struct{})

	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 0 {
			ips[line] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ips, nil
}

// filterIPs removes IPs from ipList that are found in the ipsToRemove map. The
// keys in ipsToRemove may be single IP addresses or CIDR ranges. If a key is a
// CIDR range, an IP will be removed if it falls within that range.
func filterIPs(ipList []net.IP, ipsToRemove map[string]struct{}) []net.IP {
	filtered := []net.IP{}

	// If there's nothing to filter, return the original list.
	if len(ipsToRemove) == 0 {
		return ipList
	}

	for _, ip := range ipList {
		if _, found := ipsToRemove[ip.String()]; found {
			continue
		}

		// Check for CIDR matches.
		for cidr := range ipsToRemove {
			_, netCIDR, err := net.ParseCIDR(cidr)
			if err == nil && netCIDR.Contains(ip) {
				continue
			}
			filtered = append(filtered, ip)
		}
	}
	return filtered
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
