package threatfeed

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/console"
)

// atomTemplates is the global cache for pre-compiled Atom feed templates.
var atomTemplates = template.Must(template.ParseFS(templateFS, "templates/atom/*.xml"))

// stat represents a snapshot of threatfeed statistics for a specific time.
type stat struct {
	Timestamp    time.Time `json:"timestamp"`
	FeedSize     int       `json:"feed_size"`
	NewIPs       int       `json:"new_ips"`
	ActiveIPs    int       `json:"active_ips"`
	Hits         int       `json:"hits"`
	MostHits     []ipScore `json:"most_hits,omitempty"`
	OldestActive []ipScore `json:"oldest_active,omitempty"`
}

// ipScore pairs an IP address with a counter, used for ranking (such as: most
// hits or oldest active).
type ipScore struct {
	IP    netip.Addr `json:"ip"`
	Count int        `json:"count"`
}

// history serves as a container for recorded stats and alerts.
type history struct {
	AtomID string  `json:"atom_id"`
	Weekly []stat  `json:"weekly_history"`
	Daily  []stat  `json:"daily_history"`
	Hourly []stat  `json:"hourly_history"`
	Alerts []alert `json:"alerts"`
}

// reporter manages the reporting history, tracks statistics, coordinates
// alerting, and synchronizes saving to disk. It serves as the primary data
// source for Atom feeds.
type reporter struct {
	sync.RWMutex
	history  *history
	settings *config.Reporting
	diskMu   sync.Mutex
}

// newReporter initializes a new reporter instance using the provided
// reporting settings.
func newReporter(cfg *config.Reporting) *reporter {
	return &reporter{
		history: &history{
			Weekly: []stat{},
			Daily:  []stat{},
			Hourly: []stat{},
			Alerts: []alert{},
		},
		settings: cfg,
	}
}

// reportInterval specifies the reporting period for data collection.
type reportInterval int

const (
	hourly reportInterval = iota + 1 // hourly data collection
	daily                            // daily data collection
	weekly                           // weekly data collection
)

func (i reportInterval) IsHourly() bool { return i == hourly }
func (i reportInterval) IsDaily() bool  { return i == daily }
func (i reportInterval) IsWeekly() bool { return i == weekly }

// run generates a report for the specified interval. It pulls the current
// threatfeed statistics, calculates IP rankings, updates the reporting
// history, and saves the results to disk.
func (rpt *reporter) run(interval reportInterval) error {
	s, snaps := rpt.pullStats(interval)

	// Calculate IP rankings (most hits / oldest active).
	if interval == daily || interval == weekly {
		rankIPs(&s, snaps)
	}

	// Update the report history.
	rpt.Lock()
	switch interval {
	case hourly:
		rpt.history.Hourly = append(rpt.history.Hourly, s)
		if len(rpt.history.Hourly) > 48 {
			rpt.history.Hourly = rpt.history.Hourly[1:]
		}
	case daily:
		rpt.history.Daily = append(rpt.history.Daily, s)
		if len(rpt.history.Daily) > 30 {
			rpt.history.Daily = rpt.history.Daily[1:]
		}
	case weekly:
		rpt.history.Weekly = append(rpt.history.Weekly, s)
		if len(rpt.history.Weekly) > 12 {
			rpt.history.Weekly = rpt.history.Weekly[1:]
		}
	}
	rpt.Unlock()

	// Save to disk.
	return rpt.save()
}

// ipSnapshot is a copy of an IP address entry from the threatfeed database.
// Used for ranking and reporting statistics.
type ipSnapshot struct {
	ip   netip.Addr
	hits int
	age  time.Duration
}

// pullStats extracts threatfeed statistics for the specified interval and
// resets the per-IP hit counters to prepare for the next reporting period.
func (rpt *reporter) pullStats(interval reportInterval) (stat, []ipSnapshot) {
	now := time.Now()
	var threshold time.Time
	switch interval {
	case hourly:
		threshold = now.Add(-time.Hour)
	case daily:
		threshold = now.AddDate(0, 0, -1)
	case weekly:
		threshold = now.AddDate(0, 0, -7)
	}

	db.Lock()
	defer db.Unlock()

	s := stat{
		Timestamp: now,
		FeedSize:  len(db.entries),
	}

	var snaps []ipSnapshot
	if interval != hourly {
		snaps = make([]ipSnapshot, 0, s.FeedSize)
	}

	for ip, entry := range db.entries {
		if isExcluded(ip) {
			continue
		}

		if entry.added.After(threshold) {
			s.NewIPs++
		}
		if entry.lastSeen.After(threshold) {
			s.ActiveIPs++
		}

		switch interval {
		case daily:
			s.Hits += entry.dailyHits
			snaps = append(snaps, ipSnapshot{
				ip:   ip,
				hits: entry.dailyHits,
				age:  now.Sub(entry.added),
			})
			entry.dailyHits = 0
		case weekly:
			s.Hits += entry.weeklyHits
			snaps = append(snaps, ipSnapshot{
				ip:   ip,
				hits: entry.weeklyHits,
				age:  now.Sub(entry.added),
			})
			entry.weeklyHits = 0
		}
	}

	if interval == hourly {
		s.Hits = db.hourlyHits
		db.hourlyHits = 0
	}

	db.hasChanged.Store(true)
	return s, snaps
}

// rankIPs updates the provided report statistic with the top 5 most active and
// oldest entries from the provided slice of IP snapshots.
func rankIPs(s *stat, snaps []ipSnapshot) {
	if len(snaps) == 0 {
		return
	}
	limit := min(len(snaps), 5)

	// Rank by most hits.
	slices.SortFunc(snaps, func(a, b ipSnapshot) int {
		return cmp.Compare(b.hits, a.hits)
	})
	for i := range limit {
		s.MostHits = append(s.MostHits, ipScore{
			IP:    snaps[i].ip,
			Count: snaps[i].hits,
		})
	}

	// Rank by oldest active.
	slices.SortFunc(snaps, func(a, b ipSnapshot) int {
		return cmp.Compare(b.age, a.age)
	})
	for i := range limit {
		s.OldestActive = append(s.OldestActive, ipScore{
			IP:    snaps[i].ip,
			Count: int(snaps[i].age.Hours() / 24),
		})
	}
}

// load restores saved statistics and alerts from disk during startup. It also
// ensures a persistent Atom ID exists and creates an initial history file if
// it's missing.
func (rpt *reporter) load() {
	data, err := os.ReadFile(rpt.settings.HistoryPath)

	rpt.Lock()

	if err == nil {
		_ = json.Unmarshal(data, rpt.history)
	}

	// Generate a new Atom ID, if needed.
	needSave := false
	if rpt.history.AtomID == "" {
		rpt.history.AtomID = generateAtomID()
		needSave = true
	}

	// Ensure slices are never nil.
	if rpt.history.Weekly == nil {
		rpt.history.Weekly = []stat{}
	}
	if rpt.history.Daily == nil {
		rpt.history.Daily = []stat{}
	}
	if rpt.history.Hourly == nil {
		rpt.history.Hourly = []stat{}
	}
	if rpt.history.Alerts == nil {
		rpt.history.Alerts = []alert{}
	}

	rpt.Unlock()

	if needSave {
		if err := rpt.save(); err != nil {
			console.Error(console.Feed, "Couldn't save initial report file: %v", err)
		}
	}
}

// save records the in-memory reporting state (statistics and alerts) to disk.
func (rpt *reporter) save() error {
	if rpt.settings.HistoryPath == "" {
		return nil
	}

	rpt.diskMu.Lock()
	defer rpt.diskMu.Unlock()

	// Encode to JSON.
	rpt.RLock()
	data, err := json.MarshalIndent(rpt.history, "", "  ")
	rpt.RUnlock()
	if err != nil {
		return fmt.Errorf("failed to encode json: %w", err)
	}

	// Prepare a temp file.
	tmpFile := rpt.settings.HistoryPath + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open temp file: %w", err)
	}
	defer os.Remove(tmpFile)
	defer f.Close()

	// Write the data.
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Commit to storage and close the temp file.
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Replace (or create) the history file with the temp file.
	if err := os.Rename(tmpFile, rpt.settings.HistoryPath); err != nil {
		return fmt.Errorf("failed to commit history file: %w", err)
	}

	return nil
}

// startHourly initializes a background ticker that records a new statistics
// snapshot once per hour.
func (rpt *reporter) startHourly() {
	// Sleep until the top of the next hour. This ensures we don't record
	// partial hours.
	nextHour := time.Now().Truncate(time.Hour).Add(time.Hour)
	time.Sleep(time.Until(nextHour))

	db.Lock()
	db.hourlyHits = 0
	db.Unlock()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		err := rpt.run(hourly)
		if err != nil {
			console.Error(console.Feed, "Couldn't save hourly statistics: %v", err)
		}
	}
}

// startDaily initializes a background timer that records a new statistics
// snapshot once per day.
func (rpt *reporter) startDaily() {
	for {
		// Target configured time.
		timer := time.NewTimer(durationUntil(-1, rpt.settings.Daily.Hour, rpt.settings.Daily.Minute))
		<-timer.C
		timer.Stop()

		if err := rpt.run(daily); err != nil {
			console.Error(console.Feed, "Couldn't save daily statistics: %v", err)
		}
	}
}

// startWeekly initializes a background timer that records a new statistics
// snapshot once per week.
func (rpt *reporter) startWeekly() {
	for {
		// Target configured day and time.
		timer := time.NewTimer(durationUntil(
			rpt.settings.Weekly.Weekday,
			rpt.settings.Weekly.Hour,
			rpt.settings.Weekly.Minute),
		)
		<-timer.C
		timer.Stop()

		if err := rpt.run(weekly); err != nil {
			console.Error(console.Feed, "Couldn't save weekly statistics: %v", err)
		}
	}
}

// serveReport serves reports in either Atom or JSON format. It routes requests
// to the appropriate handler based on the requested path.
func (rpt *reporter) serveReport(w http.ResponseWriter, r *http.Request) {
	// Extract the {type} wildcard from the path.
	path := r.PathValue("type")

	// Branch based on the extension.
	if strings.HasSuffix(path, ".json") {
		rpt.serveJSON(w, path)
		return
	}

	if strings.HasSuffix(path, ".xml") {
		rpt.serveAtom(w, r, path)
		return
	}

	http.Error(w, "Not Found", http.StatusNotFound)
}

// serveAtom generates an Atom XML feed from the reporting history (statistics
// and alerts). It identifies the report type by path and is the endpoint used
// by clients to subscribe to Atom feeds.
func (rpt *reporter) serveAtom(w http.ResponseWriter, r *http.Request, path string) {
	var records any
	var id string
	var tmpl string
	var updated time.Time
	var interval reportInterval

	rpt.RLock()
	id = rpt.history.AtomID
	switch path {
	case "hourly.xml":
		records = slices.Clone(rpt.history.Hourly)
		interval = hourly
		tmpl = "reports.xml"
	case "daily.xml":
		records = slices.Clone(rpt.history.Daily)
		interval = daily
		tmpl = "reports.xml"
	case "weekly.xml":
		records = slices.Clone(rpt.history.Weekly)
		interval = weekly
		tmpl = "reports.xml"
	case "alerts.xml":
		records = slices.Clone(rpt.history.Alerts)
		tmpl = "alerts.xml"
	default:
		rpt.RUnlock()
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	rpt.RUnlock()

	// Reverse the slices. Atom feeds typically list newest entries first.
	switch v := records.(type) {
	case []stat:
		if len(v) > 0 {
			updated = v[len(v)-1].Timestamp
			slices.Reverse(v)
		}
	case []alert:
		if len(v) > 0 {
			updated = v[len(v)-1].Timestamp
			slices.Reverse(v)
		}
	}

	// Default updated to now if slices were empty.
	if updated.IsZero() {
		updated = time.Now()
	}

	proto := "http://"
	if r.TLS != nil {
		proto = "https://"
	}

	data := struct {
		Records  any
		ID       string
		Updated  time.Time
		Link     string
		Path     string
		Interval reportInterval
	}{
		Records:  records,
		ID:       id,
		Updated:  updated,
		Link:     proto + r.Host,
		Path:     path,
		Interval: interval,
	}

	w.Header().Set("Content-Type", "application/atom+xml")
	_ = atomTemplates.ExecuteTemplate(w, tmpl, data)
}

// serveJSON serves report records in JSON format. The records returned depend
// on the requested path.
func (rpt *reporter) serveJSON(w http.ResponseWriter, path string) {
	var data any

	rpt.RLock()
	switch path {
	case "hourly.json":
		data = slices.Clone(rpt.history.Hourly)
	case "daily.json":
		data = slices.Clone(rpt.history.Daily)
	case "weekly.json":
		data = slices.Clone(rpt.history.Weekly)
	case "alerts.json":
		data = slices.Clone(rpt.history.Alerts)
	case "all.json":
		data = rpt.history
	default:
		rpt.RUnlock()
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	rpt.RUnlock()

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	w.Header().Set("Content-Type", "application/json")
	if err := encoder.Encode(data); err != nil {
		console.Error(console.Feed, "Failed to serve JSON report: %v", err)
	}
}

// durationUntil calculates the time remaining until the next occurrence of a
// specific weekday and hour. For daily tasks, pass -1 as the targetDay.
func durationUntil(targetDay time.Weekday, targetHour int, targetMinute int) time.Duration {
	now := time.Now()

	// Start with today at the target hour.
	next := time.Date(now.Year(), now.Month(), now.Day(), targetHour, targetMinute, 0, 0, now.Location())

	// If a specific weekday is requested, find the next occurrence of it.
	if targetDay >= 0 {
		daysUntil := (int(targetDay) - int(now.Weekday()) + 7) % 7
		next = next.AddDate(0, 0, daysUntil)
	}

	// If the target time has already passed, move to the next occurrence.
	if !now.Before(next) {
		if targetDay >= 0 {
			next = next.AddDate(0, 0, 7)
		} else {
			next = next.AddDate(0, 0, 1)
		}
	}

	return time.Until(next)
}

// generateAtomID returns a 16-character hex ID to serve as a persistent
// identifier for Atom feeds. It is designed to be unique across installs and
// consistent across restarts.
func generateAtomID() string {
	host, _ := os.Hostname()
	ip := config.GetHostIP()

	// Attempt to read /etc/machine-id for a unique/persistent fingerprint.
	// Capped at 128 bytes for safety. It provides extra uniqueness if present,
	// but fine if the file doesn't exist.
	var mid string
	if f, err := os.Open("/etc/machine-id"); err == nil {
		defer f.Close()
		r := io.LimitReader(f, 128)
		if b, err := io.ReadAll(r); err == nil {
			mid = strings.TrimSpace(string(b))
		}
	}

	combined := host + ":" + ip + ":" + mid

	// Return the first 16 hex characters of the hashed values. Missing values
	// default to empty strings and always result in a valid hash.
	return fmt.Sprintf("%x", sha256.Sum256([]byte(combined)))[:16]
}
