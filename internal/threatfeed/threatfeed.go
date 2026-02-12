package threatfeed

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// dateFormat specifies the timestamp format used for threatfeed entries.
	dateFormat = time.RFC3339Nano

	// maxObservations is the maximum number of interactions the threatfeed
	// will record for each IP.
	maxObservations = 999_999_999
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

// Update records a honeypot interaction for the given IP address in the
// threatfeed database.
func Update(ip netip.Addr) {
	// Filter out invalid, loopback, and private IPs (if configured).
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || (!cfg.ThreatFeed.IsPrivateIncluded && ip.IsPrivate()) {
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
func (d *threatDB) loadCSV() error {
	d.Lock()
	defer d.Unlock()

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

		d.entries[ip] = &threat{added: added, lastSeen: lastSeen, observations: count}
	}
	return nil
}

// saveCSV writes the threatfeed to a CSV file for persistence. This allows the
// threatfeed to be restored after a restart. It is independent of the live
// in-memory feed.
func (d *threatDB) saveCSV() error {
	// Copy db to a temporary slice, to minimize lock time.
	d.Lock()
	tempDB := make([]threatRecord, 0, len(d.entries))
	for ip, t := range d.entries {
		tempDB = append(tempDB, threatRecord{
			IP:           ip,
			Added:        t.added,
			LastSeen:     t.lastSeen,
			Observations: t.observations,
		})
	}
	d.Unlock()

	// Prepare a temp file.
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
	// Write the entries.
	for _, t := range tempDB {
		_, err := fmt.Fprintf(w, "%s,%s,%s,%d\n",
			t.IP,
			t.Added.Format(dateFormat),
			t.LastSeen.Format(dateFormat),
			t.Observations,
		)
		if err != nil {
			return err
		}
	}

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
func (d *threatDB) deleteExpired() {
	if cfg.ThreatFeed.ExpiryHours <= 0 {
		return
	}

	cutoff := time.Now().Add(-time.Hour * time.Duration(cfg.ThreatFeed.ExpiryHours))
	isModified := false

	d.Lock()
	defer d.Unlock()

	for ip, t := range d.entries {
		if t.lastSeen.Before(cutoff) {
			delete(d.entries, ip)
			isModified = true
		}
	}

	if isModified {
		d.hasChanged.Store(true)
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
