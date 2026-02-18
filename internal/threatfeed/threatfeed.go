package threatfeed

import (
	"bufio"
	"cmp"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/r-smith/deceptifeed/internal/stix"
)

// threat stores the interaction history for a unique IP address in the
// threatfeed.
type threat struct {
	// added is the timestamp when the IP was first stored in the threatfeed.
	added time.Time

	// lastSeen is the timestamp of the most recent activity for this IP.
	lastSeen time.Time

	// observations is the total number of times this IP has been detected.
	observations int
}

// threatDB provides a thread-safe container for managing records in the
// threatfeed database.
type threatDB struct {
	sync.Mutex

	// entries stores all tracked IP addresses and their interaction history.
	entries map[netip.Addr]*threat

	// hasChanged indicates if the in-memory data has been modified since the
	// last save to disk.
	hasChanged atomic.Bool
}

const (
	// dateFormat specifies the timestamp format used for threatfeed entries.
	dateFormat = time.RFC3339Nano
)

var (
	// db is the global instance of the threatfeed database used to track IP
	// address activity. It serves as the central repository for all recorded
	// honeypot interactions and is the source for serving the feed to clients.
	db = &threatDB{
		entries: make(map[netip.Addr]*threat),
	}

	// csvHeader defines the header row for saved threatfeed data.
	csvHeader = []string{"ip", "added", "last_seen", "observations"}
)

// Update records a honeypot interaction for the given IP address in the
// threatfeed database.
func Update(ip netip.Addr) {
	const maxObservations = 999_999_999

	// Filter out invalid, loopback, private (if configured), and excluded IPs.
	ip = ip.Unmap()
	if !ip.IsValid() ||
		ip.IsLoopback() ||
		(!cfg.ThreatFeed.IsPrivateIncluded && (ip.IsPrivate() || ip.IsLinkLocalUnicast())) ||
		isExcluded(ip) {
		return
	}

	now := time.Now()

	db.Lock()
	defer db.Unlock()

	if t, ok := db.entries[ip]; ok {
		// Update existing entry.
		t.lastSeen = now
		if t.observations < maxObservations {
			t.observations++
		}
	} else {
		// Create a new entry.
		db.entries[ip] = &threat{
			added:        now,
			lastSeen:     now,
			observations: 1,
		}
	}

	db.hasChanged.Store(true)
}

// loadCSV populates the in-memory threatfeed with existing records from a CSV
// file. It restores the threatfeed state during startup.
func (tdb *threatDB) loadCSV() error {
	tdb.Lock()
	defer tdb.Unlock()

	f, err := os.Open(cfg.ThreatFeed.DatabasePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()

	reader := csv.NewReader(f)

	// Read and discard the header line.
	reader.FieldsPerRecord = -1
	if _, err := reader.Read(); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}

	// Process remaining lines with 4 fields required per line.
	reader.FieldsPerRecord = 4
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Skip over lines with the wrong number of fields.
			continue
		}

		// Parse IP.
		ip, err := netip.ParseAddr(strings.TrimSpace(record[0]))
		if err != nil {
			continue
		}

		// Parse added, defaulting to current time.
		added, err := time.Parse(dateFormat, record[1])
		if err != nil {
			added = time.Now()
		}

		// Parse lastSeen, defaulting to current time.
		lastSeen, err := time.Parse(dateFormat, record[2])
		if err != nil {
			lastSeen = time.Now()
		}

		// Parse observation count, defaulting to 1.
		count, err := strconv.Atoi(strings.TrimSpace(record[3]))
		if err != nil {
			count = 1
		}

		tdb.entries[ip] = &threat{added: added, lastSeen: lastSeen, observations: count}
	}
	return nil
}

// saveCSV writes the threatfeed to a CSV file for persistence. This allows the
// threatfeed to be restored after a restart. It is independent of the live
// in-memory feed.
func (tdb *threatDB) saveCSV() error {
	tmpFile := cfg.ThreatFeed.DatabasePath + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile)
	defer f.Close()

	// 64KB buffered writer.
	w := bufio.NewWriterSize(f, 65536)

	// Write the header row.
	if _, err := w.WriteString(strings.Join(csvHeader, ",") + "\n"); err != nil {
		return err
	}

	// Reusable buffer for AppendTo, AppendFormat, and AppendInt (reduces
	// memory allocations over netip.String, time.Format, and strconv.Itoa).
	var buf []byte

	// Write the entries.
	tdb.Lock()
	for ip, t := range tdb.entries {
		// IP.
		buf = ip.AppendTo(buf[:0])
		w.Write(buf)
		w.WriteByte(',')

		// Added.
		buf = t.added.AppendFormat(buf[:0], dateFormat)
		w.Write(buf)
		w.WriteByte(',')

		// LastSeen.
		buf = t.lastSeen.AppendFormat(buf[:0], dateFormat)
		w.Write(buf)
		w.WriteByte(',')

		// Observations.
		buf = strconv.AppendInt(buf[:0], int64(t.observations), 10)
		w.Write(buf)
		w.WriteByte('\n')
	}
	tdb.Unlock()

	// Flush the buffer, commit to storage, and close the temp file.
	if err := w.Flush(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// Replace (or create) the database file with the temp file.
	return os.Rename(tmpFile, cfg.ThreatFeed.DatabasePath)
}

// deleteExpired deletes expired threatfeed entries from the database.
func (tdb *threatDB) deleteExpired() {
	if cfg.ThreatFeed.ExpiryHours <= 0 {
		return
	}

	cutoff := time.Now().Add(-time.Hour * time.Duration(cfg.ThreatFeed.ExpiryHours))
	isModified := false

	tdb.Lock()
	defer tdb.Unlock()

	for ip, t := range tdb.entries {
		if t.lastSeen.Before(cutoff) {
			delete(tdb.entries, ip)
			isModified = true
		}
	}

	if isModified {
		tdb.hasChanged.Store(true)
	}
}

// expired determines if a threat has exceeded the configured age limit based
// on its lastSeen timestamp.
func (t *threat) expired(at time.Time) bool {
	if cfg.ThreatFeed.ExpiryHours <= 0 {
		return false
	}
	return t.lastSeen.Before(at.Add(-time.Hour * time.Duration(cfg.ThreatFeed.ExpiryHours)))
}

type (
	// threatRecord represents a threat entry formatted for client delivery.
	threatRecord struct {
		IP           netip.Addr `json:"ip"`
		Added        time.Time  `json:"added"`
		LastSeen     time.Time  `json:"last_seen"`
		Observations int        `json:"observations"`
	}

	// threatRecords represents the actual threatfeed ready to serve to clients.
	threatRecords []threatRecord

	// feedOptions define configurable options for serving the threatfeed.
	feedOptions struct {
		sortBy     sortMethod
		descending bool
		after      time.Time
		limit      int
		page       int
	}

	// sortMethod represents the method used for sorting the threatfeed.
	sortMethod int
)

const (
	byIP sortMethod = iota
	byAdded
	byLastSeen
	byObservations
)

// snapshot filters and converts the threatfeed database into a slice to serve
// to clients.
func (tdb *threatDB) snapshot(options ...feedOptions) threatRecords {
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
	tdb.Lock()
	threats := make(threatRecords, 0, len(tdb.entries))

	for ip, t := range tdb.entries {
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
	tdb.Unlock()

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
