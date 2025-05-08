package threatfeed

import (
	"bufio"
	"cmp"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/r-smith/deceptifeed/internal/stix"
)

// feedEntry represents an individual entry in the threat feed.
type feedEntry struct {
	IP           string     `json:"ip"`
	IPBytes      netip.Addr `json:"-"`
	Added        time.Time  `json:"added"`
	LastSeen     time.Time  `json:"last_seen"`
	Observations int        `json:"observations"`
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
	byObservations
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

	excludedIPs, excludedCIDR, err := parseExcludeList(cfg.ThreatFeed.ExcludeListPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read threat feed exclude list:", err)
	}

	// Parse and filter IPs from iocData into the threat feed.
	mu.Lock()
	threats := make(feedEntries, 0, len(iocData))
loop:
	for ip, ioc := range iocData {
		if ioc.expired() || !ioc.lastSeen.After(opt.seenAfter) {
			continue
		}

		parsedIP, err := netip.ParseAddr(ip)
		if err != nil || (parsedIP.IsPrivate() && !cfg.ThreatFeed.IsPrivateIncluded) {
			continue
		}

		for _, prefix := range excludedCIDR {
			if prefix.Contains(parsedIP) {
				continue loop
			}
		}

		if _, found := excludedIPs[ip]; found {
			continue
		}

		threats = append(threats, feedEntry{
			IP:           ip,
			IPBytes:      parsedIP,
			Added:        ioc.added,
			LastSeen:     ioc.lastSeen,
			Observations: ioc.observations,
		})
	}
	mu.Unlock()

	threats.applySort(opt.sortMethod, opt.sortDirection)

	return threats
}

// parseExcludeList reads IP addresses and CIDR ranges from a file. Each line
// should contain an IP address or CIDR. It returns a map of the unique IPs and
// a slice of the CIDR ranges found in the file. The file may include comments
// using "#". The "#" symbol on a line and everything after is ignored.
func parseExcludeList(filepath string) (map[string]struct{}, []netip.Prefix, error) {
	if len(filepath) == 0 {
		return nil, nil, nil
	}

	f, err := os.Open(filepath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	// `ips` stores individual IPs to exclude, and `cidr` stores CIDR networks
	// to exclude.
	ips := make(map[string]struct{})
	cidr := []netip.Prefix{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Remove comments and trim.
		if i := strings.IndexByte(line, '#'); i != -1 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		if prefix, err := netip.ParsePrefix(line); err == nil {
			cidr = append(cidr, prefix)
		} else {
			ips[line] = struct{}{}
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
			return a.IPBytes.Compare(b.IPBytes)
		})
	case byLastSeen:
		slices.SortFunc(f, func(a, b feedEntry) int {
			t := a.LastSeen.Compare(b.LastSeen)
			if t == 0 {
				return a.IPBytes.Compare(b.IPBytes)
			}
			return t
		})
	case byAdded:
		slices.SortFunc(f, func(a, b feedEntry) int {
			t := a.Added.Compare(b.Added)
			if t == 0 {
				return a.IPBytes.Compare(b.IPBytes)
			}
			return t
		})
	case byObservations:
		slices.SortFunc(f, func(a, b feedEntry) int {
			t := cmp.Compare(a.Observations, b.Observations)
			if t == 0 {
				return a.IPBytes.Compare(b.IPBytes)
			}
			return t
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
	// All objects in the collection will reference this identity as the
	// creator.
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

		// Generate a deterministic identifier using the IP address represented
		// as a STIX IP pattern and structured as a JSON string. Example:
		// {"pattern":"[ipv4-addr:value='127.0.0.1']"}
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
			Confidence:     100,
			Lang:           "en",
			Labels:         []string{"honeypot-interaction"},
			CreatedByRef:   stix.DeceptifeedID,
		})
	}
	return result
}

// convertToSightings converts IP addresses from the threat feed into a
// collection of STIX Sighting objects.
func (f feedEntries) convertToSightings() []stix.Object {
	if len(f) == 0 {
		return []stix.Object{}
	}

	const indicator = "indicator"
	const sighting = "sighting"
	const maxCount = 999_999_999 // Maximum count according to STIX 2.1 specification.
	result := make([]stix.Object, 0, len(f)+1)

	// Add the Deceptifeed `Identity` as the first object in the collection.
	// All objects in the collection will reference this identity as the
	// creator.
	result = append(result, stix.DeceptifeedIdentity())

	for _, entry := range f {
		pattern := "[ipv4-addr:value = '"
		if strings.Contains(entry.IP, ":") {
			pattern = "[ipv6-addr:value = '"
		}
		pattern = pattern + entry.IP + "']"

		count := min(entry.Observations, maxCount)

		// Generate a deterministic identifier using the IP address represented
		// as a STIX IP pattern and structured as a JSON string. Example:
		// {"pattern":"[ipv4-addr:value='127.0.0.1']"}
		indicatorJSON := fmt.Sprintf("{\"pattern\":\"%s\"}", pattern)
		indicatorID := stix.DeterministicID(indicator, indicatorJSON)

		result = append(result, stix.Sighting{
			Type:             sighting,
			SpecVersion:      stix.SpecVersion,
			ID:               stix.DeterministicID(sighting, "{\"sighting_of_ref\":\""+indicatorID+"\"}"),
			Created:          entry.Added.UTC(),
			Modified:         entry.LastSeen.UTC(),
			FirstSeen:        entry.Added.UTC(),
			LastSeen:         entry.LastSeen.UTC(),
			Count:            count,
			Description:      "This IP was observed interacting with a honeypot server.",
			Confidence:       100,
			Lang:             "en",
			SightingOfRef:    indicatorID,
			WhereSightedRefs: []string{stix.DeceptifeedID},
			CreatedByRef:     stix.DeceptifeedID,
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
	// All objects in the collection will reference this identity as the
	// creator.
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
