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

	"github.com/r-smith/cti-honeypot/internal/config"
	"github.com/r-smith/cti-honeypot/internal/threatfeed"
)

// serverTimeout defines the duration after which connected clients are
// automatically disconnected, set to 30 seconds.
const serverTimeout = 30 * time.Second

// StartTCP serves as a wrapper to initialize and start a generic TCP honeypot
// server. It presents custom prompts to connected clients and logs their
// responses. This function calls the underlying startTCP function to
// perform the actual server startup.
func StartTCP(cfg *config.Config, srv *config.Server) {
	fmt.Printf("Starting TCP server on port: %s\n", srv.Port)
	if err := startTCP(cfg, srv); err != nil {
		fmt.Fprintln(os.Stderr, "The TCP server has terminated:", err)
	}
}

// startTCP starts the TCP honeypot server. It handles the server's main loop.
func startTCP(cfg *config.Config, srv *config.Server) error {
	// Start the TCP server.
	listener, err := net.Listen("tcp", ":"+srv.Port)
	if err != nil {
		return fmt.Errorf("failed to listen on port '%s': %w", srv.Port, err)
	}
	defer listener.Close()

	// Listen for and accept incoming connections.
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go handleConnection(conn, cfg, srv)
	}
}

// handleConnection is invoked when a client connects to the TCP honeypot
// server. It presents custom prompts to the client, records and logs their
// responses, and then disconnects the client. This function manages the entire
// client interaction.
func handleConnection(conn net.Conn, cfg *config.Config, srv *config.Server) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(serverTimeout))

	// Print an optional banner. Replace any occurrences of the newline escape
	// sequence "\\n" with "\r\n" (carriage return, line feed), used by
	// protocols such as Telnet and SMTP.
	if len(srv.Banner) > 0 {
		conn.Write([]byte(strings.ReplaceAll(srv.Banner, "\\n", "\r\n")))
	}

	// Present the prompts from the server configuration to the connected
	// client and record their responses.
	scanner := bufio.NewScanner(conn)
	answers := make(map[string]string)
	for i, prompt := range srv.Prompts {
		conn.Write([]byte(strings.ReplaceAll(prompt.Text, "\\n", "\r\n")))
		scanner.Scan()
		var key string
		// Each prompt includes an optional Log field that serves as the key
		// for logging. If Log is set to "none", the prompt is displayed, but
		// the response will not be logged. If Log is omitted, the default key
		// "answer00" is used, where "00" is the index plus one.
		if prompt.Log == "none" {
			// Skip logging for this entry.
			continue
		} else if len(prompt.Log) > 0 {
			key = prompt.Log
		} else {
			key = fmt.Sprintf("answer%02d", i+1)
		}
		answers[key] = scanner.Text()
	}

	// If no prompts are provided in the configuration, wait for the client to
	// send data then record the received input.
	if len(srv.Prompts) == 0 {
		scanner.Scan()
		answers["data"] = scanner.Text()
	}

	// Check if the client sent any data. If not, exit without logging.
	didProvideData := false
	for _, v := range answers {
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
	src_ip, src_port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	cfg.Logger.LogAttrs(context.Background(), slog.LevelInfo, "",
		slog.String("event_type", "tcp"),
		slog.String("source_ip", src_ip),
		slog.String("source_port", src_port),
		slog.String("sensor_ip", dst_ip),
		slog.String("sensor_port", dst_port),
		slog.String("sensor_name", config.GetHostname()),
		slog.Any("event_details", answers),
	)

	// Print a simplified version of the interaction to the console.
	fmt.Printf("[TCP] %s %v\n", src_ip, answersToString(answers))

	// Update the threat feed with the source IP address from the interaction.
	threatfeed.UpdateIoC(src_ip)
}

// answersToString converts a map of responses from custom prompts into a
// single string formatted as "key:value key:value ...". Each key-value pair
// represents a prompt and its corresponding response.
func answersToString(answers map[string]string) string {
	var keys, simpleAnswers []string

	// Collect and sort the keys.
	for key := range answers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// For each key-value pair, convert to the string "key:value".
	for _, key := range keys {
		simpleAnswers = append(simpleAnswers, fmt.Sprintf("%s:%s", key, answers[key]))
	}

	// Combine all the answers into a single string. For example, the result
	// would be formatted as: "key01:value key02:value key03:value".
	return strings.Join(simpleAnswers, " ")
}
