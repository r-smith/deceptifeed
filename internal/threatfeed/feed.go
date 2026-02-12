package threatfeed

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/r-smith/deceptifeed/internal/stix"
)

// threatRecord represents a threat entry formatted for client delivery.
type threatRecord struct {
	IP           netip.Addr `json:"ip"`
	Added        time.Time  `json:"added"`
	LastSeen     time.Time  `json:"last_seen"`
	Observations int        `json:"observations"`
}

// threatRecords represents the actual threatfeed ready to serve to clients.
type threatRecords []threatRecord

// sortMethod represents the method used for sorting the threatfeed.
type sortMethod int

const (
	byIP sortMethod = iota
	byAdded
	byLastSeen
	byObservations
)

// feedOptions define configurable options for serving the threatfeed.
type feedOptions struct {
	sortBy     sortMethod
	descending bool
	after      time.Time
	limit      int
	page       int
}

// snapshot filters and converts the threatfeed database into a slice to serve
// to clients.
func (d *threatDB) snapshot(options ...feedOptions) threatRecords {
	// Set default feed options.
	opt := feedOptions{
		sortBy:     byIP,
		descending: false,
	}
	// Override default options if provided.
	if len(options) > 0 {
		opt = options[0]
	}

	// Copy entries from threatfeed database into a slice of threatRecords.
	asOf := time.Now()
	d.Lock()
	threats := make(threatRecords, 0, len(d.entries))

	for ip, t := range d.entries {
		if t.expired(asOf) || !t.lastSeen.After(opt.after) {
			continue
		}

		if ip.IsPrivate() && !cfg.ThreatFeed.IsPrivateIncluded {
			continue
		}

		if isExcluded(ip) {
			continue
		}

		threats = append(threats, threatRecord{
			IP:           ip,
			Added:        t.added,
			LastSeen:     t.lastSeen,
			Observations: t.observations,
		})
	}
	d.Unlock()

	threats.sort(opt.sortBy, opt.descending)

	return threats
}

// sort sorts threat records based on the specified sort criteria.
func (t threatRecords) sort(method sortMethod, descending bool) {
	slices.SortFunc(t, func(a, b threatRecord) int {
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

		// If values are equal, sort by IP.
		if t == 0 && method != byIP {
			t = a.IP.Compare(b.IP)
		}

		// Inverse sort if direction is descending.
		if descending {
			return t * -1
		}
		return t
	})
}

// convertToIndicators converts the threatfeed into a collection of STIX
// STIX Indicator objects.
func (t threatRecords) convertToIndicators() []stix.Object {
	if len(t) == 0 {
		return []stix.Object{}
	}

	const indicator = "indicator"
	result := make([]stix.Object, 0, len(t)+1)

	// Add the Deceptifeed `Identity` as the first object in the collection.
	// All objects in the collection reference this identity as the creator.
	result = append(result, stix.DeceptifeedIdentity())

	for _, entry := range t {
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

// convertToSightings converts the threatfeed into a collection of STIX
// Sighting objects.
func (t threatRecords) convertToSightings() []stix.Object {
	if len(t) == 0 {
		return []stix.Object{}
	}

	const indicator = "indicator"
	const sighting = "sighting"
	const maxCount = 999_999_999 // Maximum count according to STIX 2.1 specification.
	result := make([]stix.Object, 0, len(t)+1)

	// Add the Deceptifeed `Identity` as the first object in the collection.
	// All objects in the collection reference this identity as the creator.
	result = append(result, stix.DeceptifeedIdentity())

	for _, entry := range t {
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

// convertToObservables converts the threatfeed into a collection of STIX
// Cyber-observable Objects.
func (t threatRecords) convertToObservables() []stix.Object {
	if len(t) == 0 {
		return []stix.Object{}
	}

	result := make([]stix.Object, 0, len(t)+1)

	// Add the Deceptifeed `Identity` as the first object in the collection.
	// All objects in the collection reference this identity as the creator.
	result = append(result, stix.DeceptifeedIdentity())

	for _, entry := range t {
		t := "ipv4-addr"
		if entry.IP.Is6() {
			t = "ipv6-addr"
		}

		// Generate a deterministic identifier for each IP address in the
		// threatfeed using the IP value represented as a JSON string. For
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
