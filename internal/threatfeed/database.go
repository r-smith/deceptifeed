package threatfeed

import (
	"bytes"
	"encoding/csv"
	"errors"
	"math"
	"net"
	"os"
	"strconv"
	"time"
)

// IoC represents an Indicator of Compromise (IoC) entry that makes up the
// structure of the threat feed.
type IoC struct {
	// Added records the time when an IP address is added to the threat feed.
	Added time.Time

	// LastSeen records the last time an IP was observed interacting with a
	// honeypot server.
	LastSeen time.Time

	// ThreatScore represents a score for a given IP address. It is incremented
	// based on the configured threat score of the honeypot server that the IP
	// interacted with.
	ThreatScore int
}

const (
	// dateFormat specifies the timestamp format used for CSV data.
	dateFormat = time.RFC3339
)

var (
	// csvHeader defines the header row for the threat feed data.
	csvHeader = []string{"ip", "added", "last_seen", "threat_score"}
)

// loadCSV loads existing threat feed data from a CSV file. If found, it
// populates iocData which represents the active threat feed. This function is
// called once during the initialization of the threat feed server.
func loadCSV() error {
	file, err := os.Open(configuration.DatabasePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
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
	var threatScore int
	for _, record := range records[1:] {
		ip := record[0]

		// Parse added, if available.
		if len(record) > 1 && record[1] != "" {
			added, _ = time.Parse(dateFormat, record[1])
		}

		// Parse lastSeen, if available.
		if len(record) > 2 && record[2] != "" {
			lastSeen, _ = time.Parse(dateFormat, record[2])
		}

		// Parse threat score, defaulting to 1.
		threatScore = 1
		if len(record) > 3 && record[3] != "" {
			if parsedLevel, err := strconv.Atoi(record[3]); err == nil {
				threatScore = parsedLevel
			}
		}

		iocData[ip] = &IoC{Added: added, LastSeen: lastSeen, ThreatScore: threatScore}
	}
	deleteExpired()
	return nil
}

// Update updates the threat feed with the provided source IP address and
// threat score. This function should be called by honeypot servers whenever a
// client interacts with the honeypot. If the source IP address is already in
// the threat feed, its last-seen timestamp is updated, and its threat score is
// incremented. Otherwise, the IP address is added as a new entry in the threat
// feed.
func Update(ip string, threatScore int) {
	// Check if the given IP string is a private address. The threat feed may
	// be configured to include or exclude private IPs.
	netIP := net.ParseIP(ip)
	if netIP == nil || netIP.IsLoopback() {
		return
	}
	if !configuration.IsPrivateIncluded && netIP.IsPrivate() {
		return
	}

	now := time.Now()
	mutex.Lock()
	if ioc, exists := iocData[ip]; exists {
		// Update existing entry.
		ioc.LastSeen = now
		if threatScore > 0 {
			if ioc.ThreatScore > math.MaxInt-threatScore {
				ioc.ThreatScore = math.MaxInt
			} else {
				ioc.ThreatScore += threatScore
			}
		}
	} else {
		// Create a new entry.
		iocData[ip] = &IoC{
			Added:       now,
			LastSeen:    now,
			ThreatScore: threatScore,
		}
	}
	mutex.Unlock()

	hasMapChanged = true
}

// deleteExpired deletes expired threat feed entries from the IoC map.
func deleteExpired() {
	mutex.Lock()
	defer mutex.Unlock()

	for key, value := range iocData {
		if value.expired() {
			delete(iocData, key)
		}
	}
}

// expired returns whether an IoC is considered expired based on the last
// seen date and the configured expiry hours.
func (ioc *IoC) expired() bool {
	if configuration.ExpiryHours <= 0 {
		return false
	}
	return ioc.LastSeen.Before(time.Now().Add(-time.Hour * time.Duration(configuration.ExpiryHours)))
}

// saveCSV writes the current threat feed to a CSV file. This CSV file ensures
// the threat feed data persists across application restarts. It is not the
// active threat feed.
func saveCSV() error {
	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)
	err := writer.Write(csvHeader)
	if err != nil {
		return err
	}

	mutex.Lock()
	for ip, ioc := range iocData {
		if err := writer.Write([]string{
			ip,
			ioc.Added.Format(dateFormat),
			ioc.LastSeen.Format(dateFormat),
			strconv.Itoa(ioc.ThreatScore),
		}); err != nil {
			return err
		}
	}
	mutex.Unlock()
	writer.Flush()

	if err := os.WriteFile(configuration.DatabasePath, buf.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}
