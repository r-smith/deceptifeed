package threatfeed

import (
	"cmp"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"time"
)

// handleLogsMain serves a static page listing honeypot logs available for
// viewing.
func handleLogsMain(w http.ResponseWriter, r *http.Request) {
	_ = parsedTemplates.ExecuteTemplate(w, "logs.html", "logs")
}

// handleLogs directs the request to the appropriate log parser based on the
// request path.
func handleLogs(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("logtype") {
	case "http":
		switch r.PathValue("subtype") {
		case "":
			handleLogHTTP(w)
		case "ip":
			displayStats(w, httpIPStats{})
		case "useragent":
			displayStats(w, httpUserAgentStats{})
		case "path":
			displayStats(w, httpPathStats{})
		case "query":
			displayStats(w, httpQueryStats{})
		case "method":
			displayStats(w, httpMethodStats{})
		case "host":
			displayStats(w, httpHostStats{})
		default:
			handleNotFound(w, r)
		}
	case "ssh":
		switch r.PathValue("subtype") {
		case "":
			handleLogSSH(w)
		case "ip":
			displayStats(w, sshIPStats{})
		case "client":
			displayStats(w, sshClientStats{})
		case "username":
			displayStats(w, sshUsernameStats{})
		case "password":
			displayStats(w, sshPasswordStats{})
		default:
			handleNotFound(w, r)
		}
	default:
		handleNotFound(w, r)
	}
}

// displayLogErrorPage servers an error page when there is a problem parsing
// log files.
func displayLogErrorPage(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	_ = parsedTemplates.ExecuteTemplate(w, "logs-error.html", map[string]any{"Error": err, "NavData": "logs"})
}

// handleLogSSH serves the SSH honeypot logs as a web page. It opens the
// honeypot log files, parses the data to JSON, and passes the result to an
// HTML template for rendering.
func handleLogSSH(w http.ResponseWriter) {
	l := logFiles{}
	reader, err := l.open()
	if err != nil {
		displayLogErrorPage(w, err)
		return
	}
	defer l.close()

	type Log struct {
		Time      time.Time `json:"time"`
		EventType string    `json:"event_type"`
		SourceIP  string    `json:"source_ip"`
		Details   struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"event_details"`
	}

	const maxResults = 25_000
	data := fetchEntries(reader, "ssh", func(e Log) string { return e.EventType }, maxResults)

	_ = parsedTemplates.ExecuteTemplate(w, "logs-ssh.html", map[string]any{"Data": data, "NavData": "logs"})
}

// handleLogHTTP serves the HTTP honeypot logs as a web page. It opens the
// honeypot log files, parses the data to JSON, and passes the result to an
// HTML template for rendering.
func handleLogHTTP(w http.ResponseWriter) {
	l := logFiles{}
	reader, err := l.open()
	if err != nil {
		displayLogErrorPage(w, err)
		return
	}
	defer l.close()

	type Log struct {
		Time      time.Time `json:"time"`
		EventType string    `json:"event_type"`
		SourceIP  string    `json:"source_ip"`
		Details   struct {
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"event_details"`
	}

	const maxResults = 25_000
	data := fetchEntries(reader, "http", func(e Log) string { return e.EventType }, maxResults)

	_ = parsedTemplates.ExecuteTemplate(w, "logs-http.html", map[string]any{"Data": data, "NavData": "logs"})
}

// fetchEntries decodes the last N entries of a specific log type from r.
func fetchEntries[T any](r io.Reader, target string, filter func(T) string, limit int) []T {
	d := json.NewDecoder(r)
	data := make([]T, 0, limit+1)

	for d.More() {
		var entry T
		if err := d.Decode(&entry); err != nil || filter(entry) != target {
			continue
		}
		data = append(data, entry)
		if len(data) > limit {
			data = data[1:]
		}
	}
	slices.Reverse(data)
	return data
}

// displayStats handles the processing and rendering of statistics for a given
// field. It reads honeypot log data, counts the occurrences of `field` and
// displays the results.
func displayStats(w http.ResponseWriter, fc fieldCounter) {
	l := logFiles{}
	reader, err := l.open()
	if err != nil {
		displayLogErrorPage(w, err)
		return
	}
	defer l.close()

	fieldCounts := fc.count(reader)

	results := make([]statsResult, 0, len(fieldCounts))
	for k, v := range fieldCounts {
		results = append(results, statsResult{Field: k, Count: v})
	}
	slices.SortFunc(results, func(a, b statsResult) int {
		return cmp.Or(
			-cmp.Compare(a.Count, b.Count),
			cmp.Compare(a.Field, b.Field),
		)
	})

	_ = parsedTemplates.ExecuteTemplate(
		w,
		"logs-stats.html",
		map[string]any{
			"Data":    results,
			"Header":  fc.title(),
			"NavData": "logs",
		},
	)
}

// statsResult holds a specific value for field and its associated count.
type statsResult struct {
	Field string
	Count int
}

// fieldCounter is the interface that wraps the count and title methods.
//
// count returns the unique values and their counts from a JSON log.
//
// title returns a friendly name for the log field and is used as a page header
// when displaying results.
type fieldCounter interface {
	count(io.Reader) map[string]int
	title() string
}

// eventTyper is the interface that wraps the eventType method.
//
// eventType returns the event_type value from a JSON log entry.
type eventTyper interface {
	eventType() string
}

// fieldCount decodes JSON logs from r, filters by the target event type, and
// returns a map of extracted values and their occurrence counts.
func fieldCount[T eventTyper](r io.Reader, target string, extractor func(T) string) map[string]int {
	counts := make(map[string]int)
	d := json.NewDecoder(r)

	for d.More() {
		var entry T
		if err := d.Decode(&entry); err != nil {
			continue
		}

		if entry.eventType() != target {
			continue
		}

		counts[extractor(entry)]++
	}
	return counts
}

// sshIPStats extracts counts source IP addresses from SSH logs.
type sshIPStats struct {
	EventType string `json:"event_type"`
	SourceIP  string `json:"source_ip"`
}

func (s sshIPStats) eventType() string { return s.EventType }
func (sshIPStats) title() string       { return "Source IP" }
func (sshIPStats) count(r io.Reader) map[string]int {
	return fieldCount(r, "ssh", func(e sshIPStats) string { return e.SourceIP })
}

// sshClientStats extracts and counts client versions from SSH logs.
type sshClientStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Client string `json:"ssh_client"`
	} `json:"event_details"`
}

func (s sshClientStats) eventType() string { return s.EventType }
func (sshClientStats) title() string       { return "SSH Client" }
func (sshClientStats) count(r io.Reader) map[string]int {
	return fieldCount(r, "ssh", func(e sshClientStats) string { return e.Details.Client })
}

// sshUsernameStats extracts and counts login usernames from SSH logs.
type sshUsernameStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Username string `json:"username"`
	} `json:"event_details"`
}

func (s sshUsernameStats) eventType() string { return s.EventType }
func (sshUsernameStats) title() string       { return "Username" }
func (sshUsernameStats) count(r io.Reader) map[string]int {
	return fieldCount(r, "ssh", func(e sshUsernameStats) string { return e.Details.Username })
}

// sshPasswordStats extracts and counts login passwords from SSH logs.
type sshPasswordStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Password string `json:"password"`
	} `json:"event_details"`
}

func (s sshPasswordStats) eventType() string { return s.EventType }
func (sshPasswordStats) title() string       { return "Password" }
func (sshPasswordStats) count(r io.Reader) map[string]int {
	return fieldCount(r, "ssh", func(e sshPasswordStats) string { return e.Details.Password })
}

// httpIPStats extracts and counts source IP addresses from HTTP logs.
type httpIPStats struct {
	EventType string `json:"event_type"`
	SourceIP  string `json:"source_ip"`
}

func (h httpIPStats) eventType() string { return h.EventType }
func (httpIPStats) title() string       { return "Source IP" }
func (httpIPStats) count(r io.Reader) map[string]int {
	return fieldCount(r, "http", func(e httpIPStats) string { return e.SourceIP })
}

// httpUserAgentStats extracts and counts User-Agent strings from HTTP logs.
type httpUserAgentStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		UserAgent string `json:"user_agent"`
	} `json:"event_details"`
}

func (h httpUserAgentStats) eventType() string { return h.EventType }
func (httpUserAgentStats) title() string       { return "User-Agent" }
func (httpUserAgentStats) count(r io.Reader) map[string]int {
	return fieldCount(r, "http", func(e httpUserAgentStats) string { return e.Details.UserAgent })
}

// httpPathStats extracts and counts URL paths from HTTP logs.
type httpPathStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Path string `json:"path"`
	} `json:"event_details"`
}

func (h httpPathStats) eventType() string { return h.EventType }
func (httpPathStats) title() string       { return "Path" }
func (httpPathStats) count(r io.Reader) map[string]int {
	return fieldCount(r, "http", func(e httpPathStats) string { return e.Details.Path })
}

// httpQueryStats extracts and counts query strings from HTTP logs.
type httpQueryStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Query string `json:"query"`
	} `json:"event_details"`
}

func (h httpQueryStats) eventType() string { return h.EventType }
func (httpQueryStats) title() string       { return "Query String" }
func (httpQueryStats) count(r io.Reader) map[string]int {
	return fieldCount(r, "http", func(e httpQueryStats) string { return e.Details.Query })
}

// httpMethodStats extracts and counts HTTP request methods from HTTP logs.
type httpMethodStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Method string `json:"method"`
	} `json:"event_details"`
}

func (h httpMethodStats) eventType() string { return h.EventType }
func (httpMethodStats) title() string       { return "HTTP Method" }
func (httpMethodStats) count(r io.Reader) map[string]int {
	return fieldCount(r, "http", func(e httpMethodStats) string { return e.Details.Method })
}

// httpHostStats extracts and counts Host headers from HTTP logs.
type httpHostStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Host string `json:"host"`
	} `json:"event_details"`
}

func (h httpHostStats) eventType() string { return h.EventType }
func (httpHostStats) title() string       { return "Host Header" }
func (httpHostStats) count(r io.Reader) map[string]int {
	return fieldCount(r, "http", func(e httpHostStats) string { return e.Details.Host })
}

// logFiles represents open honeypot log files and their associate io.Reader.
type logFiles struct {
	files []*os.File
}

// open opens all honeypot log files and returns an io.MultiReader that
// combines all of the logs.
func (l *logFiles) open() (io.Reader, error) {
	paths := []string{}
	seenPaths := make(map[string]bool)

	// Determine unique log paths.
	for _, s := range cfg.Servers {
		p := s.LogPath
		if seenPaths[p] {
			continue
		}
		// Add p.1 and p.
		paths = append(paths, p+".1", p)
		seenPaths[p] = true
	}

	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			l.close()
			return nil, err
		}
		l.files = append(l.files, f)
	}

	if len(l.files) == 0 {
		return nil, errors.New("no log files found")
	}

	readers := make([]io.Reader, 0, len(l.files))
	for _, f := range l.files {
		readers = append(readers, f)
	}

	return io.MultiReader(readers...), nil
}

// close closes all honeypot log files.
func (l *logFiles) close() {
	for _, f := range l.files {
		_ = f.Close()
	}
}
