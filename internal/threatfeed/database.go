package threatfeed

import (
	"bytes"
	"encoding/csv"
	"errors"
	"net"
	"os"
	"strings"
	"time"
)

// IoC represents an Indicator of Compromise (IoC) entry in the threat feed
// database. The database is in CSV format, with each row containing an IP
// address and its associated IoC data.
type IoC struct {
	LastSeen time.Time
}

const (
	// csvHeader defines the header row for the threat feed database.
	csvHeader = "ip,last_seen"

	// dateFormat specifies the timestamp format used for CSV data.
	dateFormat = time.RFC3339
)

// loadIoC reads IoC data from an existing CSV database. If found, it
// populates iocMap. This function is called once during the initialization of
// the threat feed server.
func loadIoC() error {
	file, err := os.Open(configuration.DatabasePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}
	if len(records) < 2 {
		return nil
	}

	var lastSeen time.Time
	for _, record := range records[1:] {
		ip := record[0]
		if len(record) > 1 && record[1] != "" {
			lastSeen, _ = time.Parse(dateFormat, record[1])
		}
		iocMap[ip] = &IoC{LastSeen: lastSeen}
	}
	return nil
}

// UpdateIoC updates the IoC map. This function is called by honeypot servers
// each time a client interacts with the honeypot.
func UpdateIoC(ip string) {
	mutex.Lock()
	defer mutex.Unlock()

	// Check if the given IP string is a private address. The threat feed may
	// be configured to include or exclude private IPs.
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return
	}
	if !configuration.IsPrivateIncluded && netIP.IsPrivate() {
		return
	}

	now := time.Now()
	hasMapChanged = true
	if ioc, exists := iocMap[ip]; exists {
		// Update existing entry.
		ioc.LastSeen = now
	} else {
		// Create a new entry.
		iocMap[ip] = &IoC{
			LastSeen: now,
		}
	}

	// Remove expired entries from iocMap.
	removeExpired()
}

// removeExpired checks the IoC map for entries that have expired based on
// their last seen date and the configured expiry hours. It deletes any expired
// entries from the map. This function should be called exclusively by
// UpdateIoC, which manages the mutex lock.
func removeExpired() {
	// If expiryHours is set to 0, entries never expire and will remain
	// indefinitely.
	if configuration.ExpiryHours <= 0 {
		return
	}

	var iocToRemove []string
	expirtyTime := time.Now().Add(-time.Hour * time.Duration(configuration.ExpiryHours))

	for key, value := range iocMap {
		if value.LastSeen.Before(expirtyTime) {
			iocToRemove = append(iocToRemove, key)
		}
	}

	for _, key := range iocToRemove {
		delete(iocMap, key)
	}
}

// saveIoC writes the current IoC map to a CSV file, ensuring the threat feed
// database persists across application restarts.
func saveIoC() error {
	mutex.Lock()
	defer mutex.Unlock()

	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)
	writer.Write(strings.Split(csvHeader, ","))
	for ip, ioc := range iocMap {
		writer.Write([]string{ip, ioc.LastSeen.Format(dateFormat)})
	}
	writer.Flush()

	if err := os.WriteFile(configuration.DatabasePath, buf.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}
