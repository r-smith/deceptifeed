package threatfeed

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
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
	ticker = time.NewTicker(20 * time.Second)

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
				deleteExpired()
				if err := saveIoC(); err != nil {
					fmt.Fprintln(os.Stderr, "Error saving Threat Feed database:", err)
				}
				hasMapChanged = false
			}
		}
	}()

	// Setup handlers and server config.
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
		fmt.Fprintln(os.Stderr, "The Threat Feed server has terminated:", err)
	}
}

// handlePlain handles HTTP requests to serve the threat feed in plain text. It
// returns a list of IP addresses that interacted with the honeypot servers.
// This is the default catch-all route handler.
func handlePlain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	for _, ip := range prepareThreatFeed() {
		_, err := w.Write([]byte(ip.String() + "\n"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to serve threat feed:", err)
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
			fmt.Fprintln(os.Stderr, "Failed to serve threat feed:", err)
		}
	}
}

// handleJSON handles HTTP requests to serve the full threat feed in JSON
// format. It returns a JSON array containing the entire IoC database (IP
// addresses and their associated data).
func handleJSON(w http.ResponseWriter, r *http.Request) {
	type iocDetailed struct {
		IP          string    `json:"ip"`
		LastSeen    time.Time `json:"last_seen"`
		ThreatScore int       `json:"threat_score"`
	}

	ipData := prepareThreatFeed()
	result := make([]iocDetailed, 0, len(ipData))
	for _, ip := range prepareThreatFeed() {
		if ioc, found := iocMap[ip.String()]; found {
			result = append(result, iocDetailed{
				IP:          ip.String(),
				LastSeen:    ioc.LastSeen,
				ThreatScore: ioc.ThreatScore,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	if err := e.Encode(map[string]interface{}{"threat_feed": result}); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to JSON:", err)
	}
}

// handleJSONSimple handles HTTP requests to serve a simplified version of the
// threat feed in JSON format. It returns a JSON array containing only the IP
// addresses from the threat feed.
func handleJSONSimple(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	if err := e.Encode(map[string]interface{}{"threat_feed": prepareThreatFeed()}); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to JSON:", err)
	}
}

// handleCSV handles HTTP requests to serve the full threat feed in CSV format.
// It returns a CSV file containing the entire IoC database (IP addresses and
// their associated data).
func handleCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"threat-feed-"+time.Now().Format("20060102-150405")+".csv\"")

	c := csv.NewWriter(w)
	if err := c.Write(csvHeader); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
		return
	}

	for _, ip := range prepareThreatFeed() {
		if ioc, found := iocMap[ip.String()]; found {
			if err := c.Write([]string{
				ip.String(),
				ioc.LastSeen.Format(time.RFC3339),
				strconv.Itoa(ioc.ThreatScore),
			}); err != nil {
				fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
				return
			}
		}
	}

	c.Flush()
	if err := c.Error(); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
	}
}

// handleCSVSimple handles HTTP requests to serve a simplified version of the
// threat feed in CSV format. It returns a CSV file containing only the IP
// addresses of the threat feed.
func handleCSVSimple(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"threat-feed-ips-"+time.Now().Format("20060102-150405")+".csv\"")

	c := csv.NewWriter(w)
	if err := c.Write([]string{"ip"}); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
		return
	}

	for _, ip := range prepareThreatFeed() {
		if err := c.Write([]string{ip.String()}); err != nil {
			fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
			return
		}
	}

	c.Flush()
	if err := c.Error(); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
	}
}

// prepareThreatFeed filters, processes, and sorts IP addresses from the IoC
// map. The resulting slice of `net.IP` represents the current threat feed to
// be served to clients.
func prepareThreatFeed() []net.IP {
	// Parse IPs from the iocMap to net.IP. Skip IPs that are expired, below
	// the minimum threat score, or are private, based on the configuration.
	mutex.Lock()
	netIPs := make([]net.IP, 0, len(iocMap))
	for ip, ioc := range iocMap {
		if ioc.expired() || ioc.ThreatScore < configuration.MinimumThreatScore {
			continue
		}

		ipParsed := net.ParseIP(ip)
		if ipParsed == nil {
			continue
		}
		if !configuration.IsPrivateIncluded && ipParsed.IsPrivate() {
			continue
		}
		netIPs = append(netIPs, ipParsed)
	}
	mutex.Unlock()

	// If an exclude list is provided, filter the IP list.
	if len(configuration.ExcludeListPath) > 0 {
		ipsToRemove, err := readIPsFromFile(configuration.ExcludeListPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to read threat feed exclude list:", err)
		} else {
			netIPs = filterIPs(netIPs, ipsToRemove)
		}
	}

	// Sort the IP addresses.
	sort.Slice(netIPs, func(i, j int) bool {
		return bytes.Compare(netIPs[i], netIPs[j]) < 0
	})

	return netIPs
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

		if netIP := net.ParseIP(ip); !netIP.IsPrivate() && !netIP.IsLoopback() {
			http.Error(w, "", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// disableCache is a middleware that sets HTTP response headers to prevent
// clients from caching the threat feed.
func disableCache(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

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
	if len(ipsToRemove) == 0 {
		return ipList
	}

	cidrNetworks := []*net.IPNet{}
	for cidr := range ipsToRemove {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
			cidrNetworks = append(cidrNetworks, ipnet)
		}
	}

	i := 0
	for _, ip := range ipList {
		if _, found := ipsToRemove[ip.String()]; found {
			continue
		}

		contains := false
		for _, ipnet := range cidrNetworks {
			if ipnet.Contains(ip) {
				contains = true
				break
			}
		}
		if !contains {
			ipList[i] = ip
			i++
		}
	}
	return ipList[:i]
}

// handleEmpty handles HTTP requests to /empty. It returns an empty body with
// status code 200. This endpoint is useful for temporarily clearing the threat
// feed data in firewalls.
func handleEmpty(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
}
