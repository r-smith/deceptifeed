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
	iocData = make(map[string]*IOC)

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
func Update(ip string) {
	// Check if the given IP string is a private address. The threat feed may
	// be configured to include or exclude private IPs.
	parsedIP, err := netip.ParseAddr(ip)
	if err != nil || parsedIP.IsLoopback() || (!cfg.ThreatFeed.IsPrivateIncluded && parsedIP.IsPrivate()) {
		return
	}

	now := time.Now()
	mu.Lock()
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
	mu.Unlock()

	dataChanged.Store(true)
}

// deleteExpired deletes expired threat feed entries from the IoC map.
func deleteExpired() {
	mu.Lock()
	defer mu.Unlock()

	for key, value := range iocData {
		if value.expired() {
			delete(iocData, key)
		}
	}
}

// expired returns whether an IoC is considered expired based on the last
// seen date and the configured expiry hours.
func (ioc *IOC) expired() bool {
	if cfg.ThreatFeed.ExpiryHours <= 0 {
		return false
	}
	return ioc.lastSeen.Before(time.Now().Add(-time.Hour * time.Duration(cfg.ThreatFeed.ExpiryHours)))
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
		ip := record[0]

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

// saveCSV writes the current threat feed to a CSV file. This CSV file ensures
// the threat feed data persists across application restarts. It is not the
// active threat feed.
func saveCSV() error {
	f, err := os.OpenFile(cfg.ThreatFeed.DatabasePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 65536)
	_, err = w.WriteString(strings.Join(csvHeader, ",") + "\n")
	if err != nil {
		return err
	}

	mu.Lock()
	for ip, ioc := range iocData {
		_, err = w.WriteString(
			fmt.Sprintf(
				"%s,%s,%s,%d\n",
				ip,
				ioc.added.Format(dateFormat),
				ioc.lastSeen.Format(dateFormat),
				ioc.observations,
			),
		)
		if err != nil {
			return err
		}
	}
	mu.Unlock()

	return w.Flush()
}
