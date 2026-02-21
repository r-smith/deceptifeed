package config

import (
	"fmt"
	"strings"
	"time"
)

// ThreatFeed defines the settings for the threatfeed server.
type ThreatFeed struct {
	Enabled           bool      `xml:"enabled"`
	Port              uint16    `xml:"port"`
	DatabasePath      string    `xml:"databasePath"`
	ExcludeListPath   string    `xml:"excludeListPath"`
	ExpiryHours       int       `xml:"threatExpiryHours"`
	IsPrivateIncluded bool      `xml:"includePrivateIPs"`
	EnableTLS         bool      `xml:"enableTLS"`
	CertPath          string    `xml:"certPath"`
	KeyPath           string    `xml:"keyPath"`
	Reporting         Reporting `xml:"reporting"`
}

// Reporting defines the settings for the threatfeed Reporting and alerting
// system.
type Reporting struct {
	HistoryPath string         `xml:"historyPath"`
	Daily       dailySchedule  `xml:"daily"`
	Weekly      weeklySchedule `xml:"weekly"`
}

// dailySchedule stores the configuration for a recurring daily event.
type dailySchedule struct {
	Time   string `xml:"time"`
	Hour   int    `xml:"-"`
	Minute int    `xml:"-"`
}

// weeklySchedule stores the configuration for a recurring weekly event. It
// extends dailySchedule to include a day of the week.
type weeklySchedule struct {
	dailySchedule
	Day     string       `xml:"day"`
	Weekday time.Weekday `xml:"-"`
}

// init prepares a daily schedule by parsing a time string and storing the
// result.
func (ds *dailySchedule) init() error {
	h, m, err := parseTime(ds.Time)
	if err != nil {
		return err
	}
	ds.Hour, ds.Minute = h, m
	return nil
}

// init prepares a weekly schedule by parsing day and time strings and storing
// the results.
func (ws *weeklySchedule) init() error {
	if err := ws.dailySchedule.init(); err != nil {
		return err
	}

	d, err := parseDay(ws.Day)
	if err != nil {
		return err
	}
	ws.Weekday = d
	return nil
}

// parseDay converts a string representation of a day (such as "Monday") into a
// time.Weekday.
func parseDay(s string) (time.Weekday, error) {
	if s == "" {
		return DefaultReportDay, nil
	}

	days := map[string]time.Weekday{
		"sunday":    time.Sunday,
		"monday":    time.Monday,
		"tuesday":   time.Tuesday,
		"wednesday": time.Wednesday,
		"thursday":  time.Thursday,
		"friday":    time.Friday,
		"saturday":  time.Saturday,
	}

	d, ok := days[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		return 0, fmt.Errorf("invalid <day>: '%s'", s)
	}
	return d, nil
}

// parseTime parses a time string in "HH:MM" format into hour and minute ints.
func parseTime(s string) (int, int, error) {
	if s == "" {
		return DefaultReportHour, 0, nil
	}

	var h, m int
	n, err := fmt.Sscanf(strings.TrimSpace(s), "%d:%d", &h, &m)
	if err != nil || n != 2 || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("invalid <time>: '%s'", s)
	}
	return h, m, nil
}
