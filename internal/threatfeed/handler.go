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
	"time"
)

// handlePlain handles HTTP requests to serve the threat feed in plain text. It
// returns a list of IP addresses that interacted with the honeypot servers.
// This is the default catch-all route handler.
func handlePlain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	for _, ip := range prepareFeed() {
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
// format. It returns a JSON array containing all IoC data (IP addresses and
// their associated data).
func handleJSON(w http.ResponseWriter, r *http.Request) {
	type iocDetailed struct {
		IP          string    `json:"ip"`
		Added       time.Time `json:"added"`
		LastSeen    time.Time `json:"last_seen"`
		ThreatScore int       `json:"threat_score"`
	}

	ipData := prepareFeed()
	result := make([]iocDetailed, 0, len(ipData))
	for _, ip := range ipData {
		if ioc, found := iocData[ip.String()]; found {
			result = append(result, iocDetailed{
				IP:          ip.String(),
				Added:       ioc.Added,
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
	if err := e.Encode(map[string]interface{}{"threat_feed": prepareFeed()}); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to JSON:", err)
	}
}

// handleCSV handles HTTP requests to serve the full threat feed in CSV format.
// It returns a CSV file containing all IoC data (IP addresses and their
// associated data).
func handleCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"threat-feed-"+time.Now().Format("20060102-150405")+".csv\"")

	c := csv.NewWriter(w)
	if err := c.Write(csvHeader); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
		return
	}

	for _, ip := range prepareFeed() {
		if ioc, found := iocData[ip.String()]; found {
			if err := c.Write([]string{
				ip.String(),
				ioc.Added.Format(dateFormat),
				ioc.LastSeen.Format(dateFormat),
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

	for _, ip := range prepareFeed() {
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

// handleSTIX2 handles HTTP requests to serve the full threat feed in STIX 2
// format. The response includes all IoC data (IP addresses and their
// associated data). The response is structured as a STIX Bundle containing
// `Indicators` (STIX Domain Objects) for each IP address in the threat feed.
func handleSTIX2(w http.ResponseWriter, r *http.Request) {
	type object struct {
		Type           string     `json:"type"`
		SpecVersion    string     `json:"spec_version"`
		ID             string     `json:"id"`
		IndicatorTypes []string   `json:"indicator_types"`
		Pattern        string     `json:"pattern"`
		PatternType    string     `json:"pattern_type"`
		Created        time.Time  `json:"created"`
		Modified       time.Time  `json:"modified"`
		ValidFrom      time.Time  `json:"valid_from"`
		ValidUntil     *time.Time `json:"valid_until,omitempty"`
		Name           string     `json:"name"`
		Description    string     `json:"description"`
	}
	type bundle struct {
		Type    string   `json:"type"`
		ID      string   `json:"id"`
		Objects []object `json:"objects"`
	}

	ipData := prepareFeed()
	objects := make([]object, 0, len(ipData))
	for _, ip := range ipData {
		if ioc, found := iocData[ip.String()]; found {
			pattern := "[ipv4-addr:value = '"
			if strings.Contains(ip.String(), ":") {
				pattern = "[ipv6-addr:value = '"
			}
			pattern = pattern + ip.String() + "']"
			var validUntil *time.Time
			if configuration.ExpiryHours > 0 {
				validUntil = new(time.Time)
				*validUntil = ioc.LastSeen.Add(time.Hour * time.Duration(configuration.ExpiryHours)).UTC()
			}
			// The STIX 2.1 specification allows for deterministic identifiers
			// for STIX Domain Objects using UUIDv5. The STIX namespace must
			// not be used. For each Indicator, generate the UUID using the
			// generic UUIDv5 DNS namespace and the string representation of
			// the IP address.
			objects = append(objects, object{
				Type:           "indicator",
				SpecVersion:    "2.1",
				ID:             "indicator--" + newUUIDv5(nsDNS, ip.String()),
				IndicatorTypes: []string{"malicious-activity"},
				Pattern:        pattern,
				PatternType:    "stix",
				Created:        ioc.Added.UTC(),
				Modified:       ioc.LastSeen.UTC(),
				ValidFrom:      ioc.Added.UTC(),
				ValidUntil:     validUntil,
				Name:           "Honeypot interaction",
				Description:    "This IP was observed interacting with a honeypot server.",
			})
		}
	}
	result := bundle{
		Type:    "bundle",
		ID:      "bundle--" + newUUIDv4(),
		Objects: objects,
	}

	w.Header().Set("Content-Type", "application/stix+json;version=2.1")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to STIX:", err)
	}
}

// handleSTIX2Simple handles HTTP requests to serve a simplified version of the
// threat feed in STIX 2 format. The response is structured as a STIX Bundle,
// with each IP address in the threat feed included as a STIX Cyber-observable
// Object.
func handleSTIX2Simple(w http.ResponseWriter, r *http.Request) {
	type object struct {
		Type        string `json:"type"`
		SpecVersion string `json:"spec_version"`
		ID          string `json:"id"`
		Value       string `json:"value"`
	}
	type bundle struct {
		Type    string   `json:"type"`
		ID      string   `json:"id"`
		Objects []object `json:"objects"`
	}

	ipData := prepareFeed()
	objects := make([]object, 0, len(ipData))
	for _, ip := range ipData {
		if _, found := iocData[ip.String()]; found {
			t := "ipv4-addr"
			if strings.Contains(ip.String(), ":") {
				t = "ipv6-addr"
			}
			// Use a STIX 2.1 deterministic identifier. For an IP address SCO,
			// the UUID portion of the identifier is generated using UUIDv5
			// with the STIX namespace and a JSON version of the value. Example
			// value: {"value":"127.0.0.1"}
			objects = append(objects, object{
				Type:        t,
				SpecVersion: "2.1",
				ID:          t + "--" + newUUIDv5(nsSTIX, "{\"value\":\""+ip.String()+"\"}"),
				Value:       ip.String(),
			})
		}
	}
	result := bundle{
		Type:    "bundle",
		ID:      "bundle--" + newUUIDv4(),
		Objects: objects,
	}

	w.Header().Set("Content-Type", "application/stix+json;version=2.1")
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	if err := e.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to STIX:", err)
	}
}

// handleEmpty handles HTTP requests to /empty. It returns an empty body with
// status code 200. This endpoint is useful for temporarily clearing the threat
// feed data in firewalls.
func handleEmpty(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
}

// prepareFeed filters, processes, and sorts IP addresses from the threat feed.
// The resulting slice of `net.IP` represents the current threat feed to be
// served to clients.
func prepareFeed() []net.IP {
	// Parse IPs from iocData to net.IP. Skip IPs that are expired, below the
	// minimum threat score, or are private, based on the configuration.
	mutex.Lock()
	netIPs := make([]net.IP, 0, len(iocData))
	for ip, ioc := range iocData {
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
		ipsToRemove, err := parseExcludeList(configuration.ExcludeListPath)
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

// parseExcludeList reads IP addresses and CIDR ranges from a file. Each line
// should contain an IP address or CIDR. It returns a map of the unique IPs and
// CIDR ranges found in the file.
func parseExcludeList(filepath string) (map[string]struct{}, error) {
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
