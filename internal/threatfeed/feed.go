package threatfeed

import (
	"bufio"
	"bytes"
	"cmp"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/r-smith/deceptifeed/internal/stix"
)

// feedEntry represents an individual entry in the threat feed.
type feedEntry struct {
	IP          string    `json:"ip"`
	IPBytes     net.IP    `json:"-"`
	Added       time.Time `json:"added"`
	LastSeen    time.Time `json:"last_seen"`
	ThreatScore int       `json:"threat_score"`
}

// feedEntries is a slice of feedEntry structs. It represents the threat feed
// served to clients. When clients request the feed, this structure is built
// from the `iocData` map. The data is then formatted and served to clients in
// the requested format.
type feedEntries []feedEntry

// sortMethod represents the method used for sorting the threat feed.
type sortMethod int

// Constants representing the possible values for sortMethod.
const (
	byIP sortMethod = iota
	byAdded
	byLastSeen
	byThreatScore
)

// sortDirection represents the direction of sorting (ascending or descending).
type sortDirection int

// Constants representing the possible values for sortDirection.
const (
	ascending sortDirection = iota
	descending
)

// feedOptions define configurable options for serving the threat feed.
type feedOptions struct {
	sortMethod    sortMethod
	sortDirection sortDirection
	seenAfter     time.Time
	limit         int
	page          int
}

// prepareFeed filters, processes, and sorts IP addresses from the threat feed.
// The resulting slice of `net.IP` represents the current threat feed to be
// served to clients.
func prepareFeed(options ...feedOptions) feedEntries {
	// Set default feed options.
	opt := feedOptions{
		sortMethod:    byIP,
		sortDirection: ascending,
	}
	// Override default options if provided.
	if len(options) > 0 {
		opt = options[0]
	}

	excludedIPs, excludedCIDR, err := parseExcludeList(configuration.ExcludeListPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read threat feed exclude list:", err)
	}

	// Parse and filter IPs from iocData into the threat feed.
	mutex.Lock()
	threats := make(feedEntries, 0, len(iocData))
loop:
	for ip, ioc := range iocData {
		if ioc.expired() || ioc.threatScore < configuration.MinimumThreatScore || !ioc.lastSeen.After(opt.seenAfter) {
			continue
		}

		parsedIP := net.ParseIP(ip)
		if parsedIP == nil || (parsedIP.IsPrivate() && !configuration.IsPrivateIncluded) {
			continue
		}

		for _, ipnet := range excludedCIDR {
			if ipnet.Contains(parsedIP) {
				continue loop
			}
		}

		if _, found := excludedIPs[ip]; found {
			continue
		}

		threats = append(threats, feedEntry{
			IP:          ip,
			IPBytes:     parsedIP,
			Added:       ioc.added,
			LastSeen:    ioc.lastSeen,
			ThreatScore: ioc.threatScore,
		})
	}
	mutex.Unlock()

	threats.applySort(opt.sortMethod, opt.sortDirection)

	return threats
}

// parseExcludeList reads IP addresses and CIDR ranges from a file. Each line
// should contain an IP address or CIDR. It returns a map of the unique IPs and
// a slice of the CIDR ranges found in the file.
func parseExcludeList(filepath string) (map[string]struct{}, []*net.IPNet, error) {
	if len(filepath) == 0 {
		return map[string]struct{}{}, []*net.IPNet{}, nil
	}

	file, err := os.Open(filepath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	// `ips` stores individual IPs to exclude, and `cidr` stores CIDR networks
	// to exclude.
	ips := make(map[string]struct{})
	cidr := []*net.IPNet{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 0 {
			if _, ipnet, err := net.ParseCIDR(line); err == nil {
				cidr = append(cidr, ipnet)
			} else {
				ips[line] = struct{}{}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return ips, cidr, nil
}

// applySort sorts the threat feed based on the specified sort method and
// direction.
func (f feedEntries) applySort(method sortMethod, direction sortDirection) {
	switch method {
	case byIP:
		slices.SortFunc(f, func(a, b feedEntry) int {
			return bytes.Compare(a.IPBytes, b.IPBytes)
		})
	case byLastSeen:
		slices.SortFunc(f, func(a, b feedEntry) int {
			return a.LastSeen.Compare(b.LastSeen)
		})
	case byAdded:
		slices.SortFunc(f, func(a, b feedEntry) int {
			return a.Added.Compare(b.Added)
		})
	case byThreatScore:
		slices.SortFunc(f, func(a, b feedEntry) int {
			return cmp.Compare(a.ThreatScore, b.ThreatScore)
		})
	}
	if direction == descending {
		slices.Reverse(f)
	}
}

// convertToIndicators converts IP addresses from the threat feed into a
// collection of STIX Indicator objects.
func (f feedEntries) convertToIndicators() []stix.Object {
	if len(f) == 0 {
		return []stix.Object{}
	}

	const indicator = "indicator"
	result := make([]stix.Object, 0, len(f)+1)

	// Add the Deceptifeed `Identity` as the first object in the collection.
	// All IP addresses in the collection will reference this identity as
	// the creator.
	result = append(result, stix.DeceptifeedIdentity())

	for _, entry := range f {
		pattern := "[ipv4-addr:value = '"
		if strings.Contains(entry.IP, ":") {
			pattern = "[ipv6-addr:value = '"
		}
		pattern = pattern + entry.IP + "']"

		// Fixed expiration: 2 months since last seen.
		validUntil := new(time.Time)
		*validUntil = entry.LastSeen.AddDate(0, 2, 0).UTC()

		// Generate a deterministic identifier for each IP address in the
		// threat feed using the STIX IP pattern represented as a JSON
		// string. For example: {"pattern":"[ipv4-addr:value='127.0.0.1']"}
		patternJSON := fmt.Sprintf("{\"pattern\":\"%s\"}", pattern)

		result = append(result, stix.Indicator{
			Type:           indicator,
			SpecVersion:    stix.SpecVersion,
			ID:             stix.DeterministicID(indicator, patternJSON),
			IndicatorTypes: []string{"malicious-activity"},
			Pattern:        pattern,
			PatternType:    "stix",
			Created:        entry.Added.UTC(),
			Modified:       entry.LastSeen.UTC(),
			ValidFrom:      entry.Added.UTC(),
			ValidUntil:     validUntil,
			Name:           "Honeypot interaction: " + entry.IP,
			Description:    "This IP was observed interacting with a honeypot server.",
			KillChains:     []stix.KillChain{{KillChain: "mitre-attack", Phase: "reconnaissance"}},
			Lang:           "en",
			Labels:         []string{"honeypot"},
			CreatedByRef:   stix.DeceptifeedID,
		})
	}
	return result
}

// convertToObservables converts IP addresses from the threat feed into a
// collection of STIX Cyber-observable Objects.
func (f feedEntries) convertToObservables() []stix.Object {
	if len(f) == 0 {
		return []stix.Object{}
	}

	result := make([]stix.Object, 0, len(f)+1)

	// Add the Deceptifeed `Identity` as the first object in the collection.
	// All IP addresses in the collection will reference this identity as
	// the creator.
	result = append(result, stix.DeceptifeedIdentity())

	for _, entry := range f {
		t := "ipv4-addr"
		if strings.Contains(entry.IP, ":") {
			t = "ipv6-addr"
		}

		// Generate a deterministic identifier for each IP address in the
		// threat feed using the IP value represented as a JSON string. For
		// example: {"value":"127.0.0.1"}
		result = append(result, stix.ObservableIP{
			Type:         t,
			SpecVersion:  stix.SpecVersion,
			ID:           stix.DeterministicID(t, "{\"value\":\""+entry.IP+"\"}"),
			Value:        entry.IP,
			CreatedByRef: stix.DeceptifeedID,
		})
	}
	return result
}
