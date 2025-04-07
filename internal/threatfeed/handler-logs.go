package threatfeed

import (
	"cmp"
	"encoding/json"
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
	d := json.NewDecoder(reader)
	data := make([]Log, 0, maxResults+1)
	for d.More() {
		var entry Log
		err := d.Decode(&entry)
		if err != nil || entry.EventType != "ssh" {
			continue
		}
		data = append(data, entry)
		if len(data) > maxResults {
			data = data[1:]
		}
	}
	slices.Reverse(data)

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
	d := json.NewDecoder(reader)
	data := make([]Log, 0, maxResults+1)
	for d.More() {
		var entry Log
		err := d.Decode(&entry)
		if err != nil || entry.EventType != "http" {
			continue
		}
		data = append(data, entry)
		if len(data) > maxResults {
			data = data[1:]
		}
	}
	slices.Reverse(data)

	_ = parsedTemplates.ExecuteTemplate(w, "logs-http.html", map[string]any{"Data": data, "NavData": "logs"})
}

// displayStats handles the processing and rendering of statistics for a given
// field. It reads honeypot log data, counts the occurrences of `field` and
// displays the results.
func displayStats(w http.ResponseWriter, field fieldCounter) {
	l := logFiles{}
	reader, err := l.open()
	if err != nil {
		displayLogErrorPage(w, err)
		return
	}
	defer l.close()

	fieldCounts := field.count(reader)

	results := []statsResult{}
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
			"Header":  field.fieldName(),
			"NavData": "logs",
		},
	)
}

// statsResult holds a specific value for field and its associated count.
type statsResult struct {
	Field string
	Count int
}

// fieldCounter is an interface that defines methods for counting occurrences
// of specific fields.
type fieldCounter interface {
	count(io.Reader) map[string]int
	fieldName() string
}

// sshIPStats is the log structure for extracting SSH IP data.
type sshIPStats struct {
	EventType string `json:"event_type"`
	SourceIP  string `json:"source_ip"`
}

func (sshIPStats) fieldName() string { return "Source IP" }

func (sshIPStats) count(r io.Reader) map[string]int {
	fieldCounts := map[string]int{}
	d := json.NewDecoder(r)
	for d.More() {
		var entry sshIPStats
		err := d.Decode(&entry)
		if err != nil || entry.EventType != "ssh" {
			continue
		}
		fieldCounts[entry.SourceIP]++
	}
	return fieldCounts
}

// sshClientStats is the log structure for extracting SSH client data.
type sshClientStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Client string `json:"ssh_client"`
	} `json:"event_details"`
}

func (sshClientStats) fieldName() string { return "SSH Client" }

func (sshClientStats) count(r io.Reader) map[string]int {
	fieldCounts := map[string]int{}
	d := json.NewDecoder(r)
	for d.More() {
		var entry sshClientStats
		err := d.Decode(&entry)
		if err != nil || entry.EventType != "ssh" {
			continue
		}
		fieldCounts[entry.Details.Client]++
	}
	return fieldCounts
}

// sshUsernameStats is the log structure for extracting SSH username data.
type sshUsernameStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Username string `json:"username"`
	} `json:"event_details"`
}

func (sshUsernameStats) fieldName() string { return "Username" }

func (sshUsernameStats) count(r io.Reader) map[string]int {
	fieldCounts := map[string]int{}
	d := json.NewDecoder(r)
	for d.More() {
		var entry sshUsernameStats
		err := d.Decode(&entry)
		if err != nil || entry.EventType != "ssh" {
			continue
		}
		fieldCounts[entry.Details.Username]++
	}
	return fieldCounts
}

// sshPasswordStats is the log structure for extracting SSH password data.
type sshPasswordStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Password string `json:"password"`
	} `json:"event_details"`
}

func (sshPasswordStats) fieldName() string { return "Password" }

func (sshPasswordStats) count(r io.Reader) map[string]int {
	fieldCounts := map[string]int{}
	d := json.NewDecoder(r)
	for d.More() {
		var entry sshPasswordStats
		err := d.Decode(&entry)
		if err != nil || entry.EventType != "ssh" {
			continue
		}
		fieldCounts[entry.Details.Password]++
	}
	return fieldCounts
}

// httpIPStats is the log structure for extracting HTTP IP data.
type httpIPStats struct {
	EventType string `json:"event_type"`
	SourceIP  string `json:"source_ip"`
}

func (httpIPStats) fieldName() string { return "Source IP" }

func (httpIPStats) count(r io.Reader) map[string]int {
	fieldCounts := map[string]int{}
	d := json.NewDecoder(r)
	for d.More() {
		var entry httpIPStats
		err := d.Decode(&entry)
		if err != nil || entry.EventType != "http" {
			continue
		}
		fieldCounts[entry.SourceIP]++
	}
	return fieldCounts
}

// httpUserAgentStats is the log structure for extracting HTTP user-agent data.
type httpUserAgentStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		UserAgent string `json:"user_agent"`
	} `json:"event_details"`
}

func (httpUserAgentStats) fieldName() string { return "User-Agent" }

func (httpUserAgentStats) count(r io.Reader) map[string]int {
	fieldCounts := map[string]int{}
	d := json.NewDecoder(r)
	for d.More() {
		var entry httpUserAgentStats
		err := d.Decode(&entry)
		if err != nil || entry.EventType != "http" {
			continue
		}
		fieldCounts[entry.Details.UserAgent]++
	}
	return fieldCounts
}

// httpPathStats is the log structure for extracting HTTP path data.
type httpPathStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Path string `json:"path"`
	} `json:"event_details"`
}

func (httpPathStats) fieldName() string { return "Path" }

func (httpPathStats) count(r io.Reader) map[string]int {
	fieldCounts := map[string]int{}
	d := json.NewDecoder(r)
	for d.More() {
		var entry httpPathStats
		err := d.Decode(&entry)
		if err != nil || entry.EventType != "http" {
			continue
		}
		fieldCounts[entry.Details.Path]++
	}
	return fieldCounts
}

// httpQueryStats is the log structure for extracting HTTP query string data.
type httpQueryStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Query string `json:"query"`
	} `json:"event_details"`
}

func (httpQueryStats) fieldName() string { return "Query String" }

func (httpQueryStats) count(r io.Reader) map[string]int {
	fieldCounts := map[string]int{}
	d := json.NewDecoder(r)
	for d.More() {
		var entry httpQueryStats
		err := d.Decode(&entry)
		if err != nil || entry.EventType != "http" {
			continue
		}
		fieldCounts[entry.Details.Query]++
	}
	return fieldCounts
}

// httpMethodStats is the log structure for extracting HTTP method data.
type httpMethodStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Method string `json:"method"`
	} `json:"event_details"`
}

func (httpMethodStats) fieldName() string { return "HTTP Method" }

func (httpMethodStats) count(r io.Reader) map[string]int {
	fieldCounts := map[string]int{}
	d := json.NewDecoder(r)
	for d.More() {
		var entry httpMethodStats
		err := d.Decode(&entry)
		if err != nil || entry.EventType != "http" {
			continue
		}
		fieldCounts[entry.Details.Method]++
	}
	return fieldCounts
}

// httpHostStats is the log structure for extracting HTTP host header data.
type httpHostStats struct {
	EventType string `json:"event_type"`
	Details   struct {
		Host string `json:"host"`
	} `json:"event_details"`
}

func (httpHostStats) fieldName() string { return "Host Header" }

func (httpHostStats) count(r io.Reader) map[string]int {
	fieldCounts := map[string]int{}
	d := json.NewDecoder(r)
	for d.More() {
		var entry httpHostStats
		err := d.Decode(&entry)
		if err != nil || entry.EventType != "http" {
			continue
		}
		fieldCounts[entry.Details.Host]++
	}
	return fieldCounts
}

// logFiles represents open honeypot log files and their associate io.Reader.
type logFiles struct {
	files   []*os.File
	readers []io.Reader
}

// open opens all honeypot log files and returns an io.MultiReader that
// combines all of the logs.
func (l *logFiles) open() (io.Reader, error) {
	paths := []string{}
	seenPaths := make(map[string]bool)

	// Helper function to ensure only unique paths are added to the slice.
	add := func(p string) {
		if seenPaths[p] {
			return
		}
		// New path. Add both the path and the path with ".1" to the slice.
		paths = append(paths, p+".1", p)
		seenPaths[p] = true
	}

	for _, s := range cfg.Servers {
		add(s.LogPath)
	}

	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		l.files = append(l.files, f)
	}

	for _, f := range l.files {
		l.readers = append(l.readers, f)
	}

	return io.MultiReader(l.readers...), nil
}

// close closes all honeypot log files.
func (l *logFiles) close() {
	for _, f := range l.files {
		_ = f.Close()
	}
}
