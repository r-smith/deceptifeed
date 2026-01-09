package tcpserver

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/eventdata"
	"github.com/r-smith/deceptifeed/internal/proxyproto"
	"github.com/r-smith/deceptifeed/internal/threatfeed"
)

// serverTimeout defines the duration after which connected clients are
// automatically disconnected, set to 30 seconds.
const serverTimeout = 30 * time.Second

// Start initializes and starts a generic TCP honeypot server. It presents
// custom prompts to connected clients and logs their responses. Interactions
// with the TCP server are sent to the threat feed.
func Start(cfg *config.Server) {
	fmt.Printf("Starting TCP server on port: %s\n", cfg.Port)
	listener, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "The TCP server on port %s has stopped: %v\n", cfg.Port, err)
		return
	}
	defer listener.Close()

	// Replace occurrences of "\n" with "\r\n". The configuration file uses
	// "\n", but CRLF is expected for TCP protocols.
	cfg.Banner = strings.ReplaceAll(cfg.Banner, "\\n", "\r\n")
	for i := range cfg.Prompts {
		cfg.Prompts[i].Text = strings.ReplaceAll(cfg.Prompts[i].Text, "\\n", "\r\n")
	}

	// Listen for and accept incoming connections.
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go handleConnection(conn, cfg)
	}
}

// handleConnection is invoked when a client connects to the TCP honeypot
// server. It presents custom prompts to the client, records and logs their
// responses, and then disconnects the client. This function manages the entire
// client interaction.
func handleConnection(conn net.Conn, cfg *config.Server) {
	defer conn.Close()

	// Record the connection details and handle Proxy Protocol if enabled.
	evt := eventdata.Connection{}
	evt.ServerIP, evt.ServerPort, _ = net.SplitHostPort(conn.LocalAddr().String())
	evt.SourceIP, _, _ = net.SplitHostPort(conn.RemoteAddr().String())

	if cfg.UseProxyProtocol {
		evt.ProxyIP = evt.SourceIP
		if extractedIP, err := proxyproto.ReadHeader(conn); err != nil {
			evt.ProxyError = err.Error()
		} else {
			evt.ProxyParsed = true
			evt.SourceIP = extractedIP
		}
	}

	logData := prepareLog(&evt, cfg)

	// Set a connection deadline.
	_ = conn.SetDeadline(time.Now().Add(serverTimeout))

	// Display initial banner to the client if configured.
	if len(cfg.Banner) > 0 {
		_, _ = conn.Write([]byte(cfg.Banner))
	}

	// Display configured prompts to the client and record the responses.
	scanner := bufio.NewScanner(conn)
	responses := make(map[string]string, len(cfg.Prompts))
	for i, prompt := range cfg.Prompts {
		_, _ = conn.Write([]byte(prompt.Text))
		scanner.Scan()
		var key string
		// Each prompt includes an optional Log field that serves as the key
		// for logging. If Log is set to "none", the prompt is displayed, but
		// the response will not be logged. If Log is omitted, the default key
		// "data00" is used, where "00" is the index plus one.
		if prompt.Log == "none" {
			continue
		} else if len(prompt.Log) > 0 {
			key = prompt.Log
		} else {
			key = fmt.Sprintf("data%02d", i+1)
		}
		responses[key] = scanner.Text()
	}

	// If no prompts are configured, wait for client input and record the
	// received data.
	if len(cfg.Prompts) == 0 {
		scanner.Scan()
		responses["data"] = scanner.Text()
	}

	// Check if the client sent any data. If not, exit without logging.
	didProvideData := false
	for _, v := range responses {
		if len(v) > 0 {
			didProvideData = true
			break
		}
	}
	if !didProvideData {
		return
	}

	// Log the event and update the threat feed.
	cfg.Logger.LogAttrs(context.Background(), slog.LevelInfo, "tcp", append(logData, slog.Any("event_details", responses))...)

	fmt.Printf("[TCP] %s %q\n", evt.SourceIP, responsesToString(responses))

	if cfg.SendToThreatFeed {
		threatfeed.Update(evt.SourceIP)
	}
}

// preparelog builds structured log fields from network connection metadata.
func prepareLog(evt *eventdata.Connection, cfg *config.Server) []slog.Attr {
	d := make([]slog.Attr, 0, 8)
	d = append(d,
		slog.String("source_ip", evt.SourceIP),
	)
	if cfg.UseProxyProtocol {
		d = append(d,
			slog.Bool("source_ip_parsed", evt.ProxyParsed),
			slog.String("source_ip_error", evt.ProxyError),
			slog.String("proxy_ip", evt.ProxyIP),
		)
	}
	d = append(d,
		slog.String("server_ip", evt.ServerIP),
		slog.String("server_port", evt.ServerPort),
		slog.String("server_name", config.Hostname),
	)
	return d
}

// responsesToString converts a map of responses from custom prompts into a
// single string formatted as "key:value key:value ...". Each key-value pair
// represents a prompt and its corresponding response.
func responsesToString(responses map[string]string) string {
	var keys, result []string

	// Collect and sort the keys.
	for key := range responses {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// For each key-value pair, convert to the string "key:value".
	for _, key := range keys {
		result = append(result, fmt.Sprintf("%s:%s", key, responses[key]))
	}

	// Combine the responses into a single string. For example, the result
	// would be formatted as: "key01:value key02:value key03:value".
	return strings.Join(result, " ")
}
