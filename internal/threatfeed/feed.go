package threatfeed

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/r-smith/deceptifeed/internal/stix"
)

// feedEntry represents an individual entry in the threat feed.
type feedEntry struct {
	IP           netip.Addr `json:"ip"`
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

	// Parse and filter IPs from iocData into the threat feed.
	asOf := time.Now()
	mu.Lock()
	threats := make(feedEntries, 0, len(iocData))

	for ip, ioc := range iocData {
		if ioc.expired(asOf) || !ioc.lastSeen.After(opt.seenAfter) {
			continue
		}

		if ip.IsPrivate() && !cfg.ThreatFeed.IsPrivateIncluded {
			continue
		}

		if isExcluded(ip) {
			continue
		}

		threats = append(threats, feedEntry{
			IP:           ip,
			Added:        ioc.added,
			LastSeen:     ioc.lastSeen,
			Observations: ioc.observations,
		})
	}
	mu.Unlock()

	threats.applySort(opt.sortMethod, opt.sortDirection)

	return threats
}

// applySort sorts the threat feed based on the specified sort method and
// direction.
func (f feedEntries) applySort(method sortMethod, direction sortDirection) {
	slices.SortFunc(f, func(a, b feedEntry) int {
		var t int
		switch method {
		case byIP:
			t = a.IP.Compare(b.IP)
		case byLastSeen:
			t = a.LastSeen.Compare(b.LastSeen)
		case byAdded:
			t = a.Added.Compare(b.Added)
		case byObservations:
			t = cmp.Compare(a.Observations, b.Observations)
		}

		// If values or equal, sort by IP.
		if t == 0 && method != byIP {
			t = a.IP.Compare(b.IP)
		}

		// Inverse sort if direction is descending.
		if direction == descending {
			return t * -1
		}
		return t
	})
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
		addrType := "ipv4-addr"
		if entry.IP.Is6() {
			addrType = "ipv6-addr"
		}
		pattern := fmt.Sprintf("[%s:value = '%s']", addrType, entry.IP)

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
			Name:           "Honeypot interaction: " + entry.IP.String(),
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
		addrType := "ipv4-addr"
		if entry.IP.Is6() {
			addrType = "ipv6-addr"
		}
		pattern := fmt.Sprintf("[%s:value = '%s']", addrType, entry.IP)

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
		if entry.IP.Is6() {
			t = "ipv6-addr"
		}

		// Generate a deterministic identifier for each IP address in the
		// threat feed using the IP value represented as a JSON string. For
		// example: {"value":"127.0.0.1"}
		result = append(result, stix.ObservableIP{
			Type:         t,
			SpecVersion:  stix.SpecVersion,
			ID:           stix.DeterministicID(t, "{\"value\":\""+entry.IP.String()+"\"}"),
			Value:        entry.IP.String(),
			CreatedByRef: stix.DeceptifeedID,
		})
	}
	return result
}
