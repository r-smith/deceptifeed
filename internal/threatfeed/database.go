package threatfeed

import (
	"bytes"
	"encoding/csv"
	"errors"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// IoC represents an Indicator of Compromise (IoC) entry in the threat feed
// database. The database is in CSV format, with each row containing an IP
// address and its associated IoC data.
type IoC struct {
	// LastSeen records the last time an IP was observed interacting with a
	// honeypot server.
	LastSeen time.Time

	// ThreatScore represents a score for a given IP address. It is incremented
	// based on the configured threat score of the honeypot server that the IP
	// interacted with.
	ThreatScore int
}

const (
	// csvHeader defines the header row for the threat feed database.
	csvHeader = "ip,last_seen,threat_score"

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
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}
	if len(records) < 2 {
		return nil
	}

	var lastSeen time.Time
	var threatScore int
	for _, record := range records[1:] {
		ip := record[0]

		// Parse lastSeen, if available.
		if len(record) > 1 && record[1] != "" {
			lastSeen, _ = time.Parse(dateFormat, record[1])
		}

		// Parse threat score, defaulting to 1.
		threatScore = 1
		if len(record) > 2 && record[2] != "" {
			if parsedLevel, err := strconv.Atoi(record[2]); err == nil {
				threatScore = parsedLevel
			}
		}

		iocMap[ip] = &IoC{LastSeen: lastSeen, ThreatScore: threatScore}
	}
	deleteExpired()
	return nil
}

// UpdateIoC updates the IoC map. This function is called by honeypot servers
// each time a client interacts with the honeypot.
func UpdateIoC(ip string, threatScore int) {
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
	if ioc, exists := iocMap[ip]; exists {
		// Update existing entry.
		ioc.LastSeen = now
		if uint(ioc.ThreatScore+threatScore) <= math.MaxInt {
			ioc.ThreatScore += threatScore
		}
	} else {
		// Create a new entry.
		iocMap[ip] = &IoC{
			LastSeen:    now,
			ThreatScore: threatScore,
		}
	}
	mutex.Unlock()

	hasMapChanged = true
}

// deleteExpired deletes expired entries from the IoC map.
func deleteExpired() {
	mutex.Lock()
	defer mutex.Unlock()

	for key, value := range iocMap {
		if value.expired() {
			delete(iocMap, key)
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

// saveIoC writes the current IoC map to a CSV file, ensuring the threat feed
// database persists across application restarts.
func saveIoC() error {
	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)
	err := writer.Write(strings.Split(csvHeader, ","))
	if err != nil {
		return err
	}

	mutex.Lock()
	for ip, ioc := range iocMap {
		err := writer.Write([]string{ip, ioc.LastSeen.Format(dateFormat), strconv.Itoa(ioc.ThreatScore)})
		if err != nil {
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
