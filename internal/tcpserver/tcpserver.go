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
	_ = conn.SetDeadline(time.Now().Add(serverTimeout))

	// Print an optional banner. Replace any occurrences of the newline escape
	// sequence "\\n" with "\r\n" (carriage return, line feed), used by
	// protocols such as Telnet and SMTP.
	if len(cfg.Banner) > 0 {
		_, _ = conn.Write([]byte(strings.ReplaceAll(cfg.Banner, "\\n", "\r\n")))
	}

	// Present the prompts from the server configuration to the connected
	// client and record their responses.
	scanner := bufio.NewScanner(conn)
	responses := make(map[string]string)
	for i, prompt := range cfg.Prompts {
		_, _ = conn.Write([]byte(strings.ReplaceAll(prompt.Text, "\\n", "\r\n")))
		scanner.Scan()
		var key string
		// Each prompt includes an optional Log field that serves as the key
		// for logging. If Log is set to "none", the prompt is displayed, but
		// the response will not be logged. If Log is omitted, the default key
		// "data00" is used, where "00" is the index plus one.
		if prompt.Log == "none" {
			// Skip logging for this entry.
			continue
		} else if len(prompt.Log) > 0 {
			key = prompt.Log
		} else {
			key = fmt.Sprintf("data%02d", i+1)
		}
		responses[key] = scanner.Text()
	}

	// If no prompts are provided in the configuration, wait for the client to
	// send data then record the received input.
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

	// Log the connection along with all responses received from the client.
	dst_ip, dst_port, _ := net.SplitHostPort(conn.LocalAddr().String())
	src_ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	cfg.Logger.LogAttrs(context.Background(), slog.LevelInfo, "",
		slog.String("event_type", "tcp"),
		slog.String("source_ip", src_ip),
		slog.String("server_ip", dst_ip),
		slog.String("server_port", dst_port),
		slog.String("server_name", config.GetHostname()),
		slog.Any("event_details", responses),
	)

	// Print a simplified version of the interaction to the console.
	fmt.Printf("[TCP] %s %q\n", src_ip, responsesToString(responses))

	// Update the threat feed with the source IP address from the interaction.
	if cfg.SendToThreatFeed {
		threatfeed.Update(src_ip, cfg.ThreatScore)
	}
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
