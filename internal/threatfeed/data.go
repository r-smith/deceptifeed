package threatfeed

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// IOC represents an Indicator of Compromise (IOC) entry that stores
// information about IP addresses that interact with the honeypot servers.
type IOC struct {
	// added records the time when an IP address is added to the threat feed.
	added time.Time

	// lastSeen records the last time an IP was observed interacting with a
	// honeypot server.
	lastSeen time.Time

	// observations tracks the total number of interactions an IP has had with
	// the honeypot servers.
	observations int
}

const (
	// dateFormat specifies the timestamp format used for threat feed entries.
	dateFormat = time.RFC3339Nano

	// maxObservations is the maximum number of interactions the threat feed
	// will record for each IP.
	maxObservations = 999_999_999
)

var (
	// iocData stores Indicator of Compromise (IOC) entries, keyed by IP
	// address. This map represents the internal structure of the threat feed.
	// It is populated with existing threat data when the server starts. The
	// map is then updated by `Update` whenever a potential attacker interacts
	// with a honeypot server. The threat feed served to clients is generated
	// based on the data in this map.
	iocData = make(map[netip.Addr]*IOC)

	// mu is to ensure thread-safe access to iocData.
	mu sync.Mutex

	// dataChanged indicates whether the IoC map has been modified since the
	// last time it was saved to disk.
	dataChanged atomic.Bool

	// csvHeader defines the header row for saved threat feed data.
	csvHeader = []string{"ip", "added", "last_seen", "observations"}
)

// Update updates the threat feed with the provided source IP address. This
// function should be called by honeypot servers whenever a client interacts
// with the honeypot. If the source IP address is already in the threat feed,
// its last-seen timestamp is updated, and its observation count is
// incremented. Otherwise, the IP address is added as a new entry.
func Update(ip netip.Addr) {
	// Check if the given IP string is a private address. The threat feed may
	// be configured to include or exclude private IPs.
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || (!cfg.ThreatFeed.IsPrivateIncluded && ip.IsPrivate()) {
		return
	}

	now := time.Now()

	mu.Lock()
	defer mu.Unlock()

	if ioc, exists := iocData[ip]; exists {
		// Update existing entry.
		ioc.lastSeen = now
		if ioc.observations < maxObservations {
			ioc.observations++
		}
	} else {
		// Create a new entry.
		iocData[ip] = &IOC{
			added:        now,
			lastSeen:     now,
			observations: 1,
		}
	}

	dataChanged.Store(true)
}

// deleteExpired deletes expired threatfeed entries from the IoC map.
func deleteExpired() {
	if cfg.ThreatFeed.ExpiryHours <= 0 {
		return
	}

	cutoff := time.Now().Add(-time.Hour * time.Duration(cfg.ThreatFeed.ExpiryHours))
	isModified := false

	mu.Lock()
	defer mu.Unlock()

	for ip, ioc := range iocData {
		if ioc.lastSeen.Before(cutoff) {
			delete(iocData, ip)
			isModified = true
		}
	}

	if isModified {
		dataChanged.Store(true)
	}
}

// expired evaluates the age of an IoC. It returns true if the duration between
// its lastSeen time and the proided time exceeds the configured expiry hours.
func (ioc *IOC) expired(at time.Time) bool {
	if cfg.ThreatFeed.ExpiryHours <= 0 {
		return false
	}
	return ioc.lastSeen.Before(at.Add(-time.Hour * time.Duration(cfg.ThreatFeed.ExpiryHours)))
}

// loadCSV loads existing threat feed data from a CSV file. If found, it
// populates iocData which represents the active threat feed. This function is
// called once during the initialization of the threat feed server.
func loadCSV() error {
	mu.Lock()
	defer mu.Unlock()

	f, err := os.Open(cfg.ThreatFeed.DatabasePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}
	if len(records) < 2 {
		return nil
	}

	var added time.Time
	var lastSeen time.Time
	var count int
	for _, record := range records[1:] {
		// Parse IP into a netip.Addr.
		ip, err := netip.ParseAddr(record[0])
		if err != nil {
			continue
		}

		// Parse added, defaulting to current time.
		added = time.Now()
		if len(record) > 1 && record[1] != "" {
			added, _ = time.Parse(dateFormat, record[1])
		}

		// Parse lastSeen, defaulting to current time.
		lastSeen = time.Now()
		if len(record) > 2 && record[2] != "" {
			lastSeen, _ = time.Parse(dateFormat, record[2])
		}

		// Parse observation count, defaulting to 1.
		count = 1
		if len(record) > 3 && record[3] != "" {
			if parsedCount, err := strconv.Atoi(record[3]); err == nil {
				count = parsedCount
			}
		}

		iocData[ip] = &IOC{added: added, lastSeen: lastSeen, observations: count}
	}
	return nil
}

// saveCSV performs an atomic save of the threatfeed to a CSV file. This file
// ensures the threatfeed persists across restarts. It is separate from the
// live in-memory feed.
func saveCSV() error {
	// Copy iocData to a temporary slice, to minimize lock time.
	mu.Lock()
	type entry struct {
		ip              netip.Addr
		added, lastSeen time.Time
		observations    int
	}
	tempData := make([]entry, 0, len(iocData))
	for ip, ioc := range iocData {
		tempData = append(tempData, entry{ip, ioc.added, ioc.lastSeen, ioc.observations})
	}
	mu.Unlock()

	// Prepare a temp file.
	tempPath := cfg.ThreatFeed.DatabasePath + ".tmp"
	f, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer os.Remove(tempPath)
	defer f.Close()

	// 64KB buffered writer.
	w := bufio.NewWriterSize(f, 65536)

	// Write the header row.
	if _, err := w.WriteString(strings.Join(csvHeader, ",") + "\n"); err != nil {
		return err
	}
	// Write the entries.
	for _, ioc := range tempData {
		_, err := fmt.Fprintf(w, "%s,%s,%s,%d\n",
			ioc.ip,
				ioc.added.Format(dateFormat),
				ioc.lastSeen.Format(dateFormat),
				ioc.observations,
		)
		if err != nil {
			return err
		}
	}

	// Flush the buffer and commit to storage.
	if err := w.Flush(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}

	// Explicitly close temp file before the rename.
	if err := f.Close(); err != nil {
		return err
	}

	// Replace (or create) the database file with the temp file.
	return os.Rename(tempPath, cfg.ThreatFeed.DatabasePath)
}
