package tcpserver

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/console"
	"github.com/r-smith/deceptifeed/internal/eventdata"
	"github.com/r-smith/deceptifeed/internal/proxyproto"
	"github.com/r-smith/deceptifeed/internal/threatfeed"
)

// Start initializes and starts a generic TCP honeypot server. It presents
// custom prompts to connected clients and logs their responses. Interactions
// with the TCP server are sent to the threatfeed.
func Start(srv *config.Server) {
	listener, err := net.Listen("tcp", ":"+srv.Port)
	if err != nil {
		console.Error(console.TCP, "Failed to start honeypot on port %s: %v", srv.Port, err)
		return
	}

	if srv.UseProxyProtocol {
		listener = &proxyproto.Listener{Listener: listener}
	}
	defer listener.Close()
	console.Info(console.TCP, "Honeypot is active and listening on port %s", srv.Port)

	// Replace occurrences of "\n" with "\r\n". The configuration file uses
	// "\n", but CRLF is expected for TCP protocols.
	srv.Banner = strings.ReplaceAll(srv.Banner, "\\n", "\r\n")
	for i := range srv.Prompts {
		srv.Prompts[i].Text = strings.ReplaceAll(srv.Prompts[i].Text, "\\n", "\r\n")
	}

	// Listen for and accept incoming connections.
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go handleConnection(conn, srv)
	}
}

// handleConnection is invoked when a client connects to the TCP honeypot
// server. It presents custom prompts to the client, records and logs their
// responses, and then disconnects the client. This function manages the entire
// client interaction.
func handleConnection(conn net.Conn, srv *config.Server) {
	defer conn.Close()

	// Record the connection metadata.
	evt := eventdata.Connection{}
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		evt.ServerIP = addr.AddrPort().Addr().Unmap()
		evt.ServerPort = addr.AddrPort().Port()
	}
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		evt.SourceIP = addr.AddrPort().Addr().Unmap()
	}

	// If the connection is Proxy Protocol wrapped, extract the metadata.
	if pconn, ok := conn.(*proxyproto.Conn); ok {
		// Record the proxy's IP.
		if rawAddr, ok := pconn.Conn.RemoteAddr().(*net.TCPAddr); ok {
			evt.ProxyIP = rawAddr.AddrPort().Addr().Unmap()
		}

		// Record the parsing results.
		if extractedIP, err := pconn.ProxyData(); err == nil && extractedIP.IsValid() {
			evt.ProxyParsed = true
		} else if err != nil {
			evt.ProxyError = err.Error()
		}
	}

	logData := prepareLog(&evt, srv)

	// Log and report the connection.
	if srv.LogConnections {
		srv.Logger.LogAttrs(context.Background(), slog.LevelInfo, "connection", logData...)
		console.Debug(console.TCP, "%s connected to port %d", evt.SourceIP, evt.ServerPort)
	}
	if srv.ReportConnections {
		threatfeed.Update(evt.SourceIP)
	}

	// Forcibly drop the connection using a TCP RST when SessionTimeout is 0.
	if srv.SessionTimeout == 0 {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0)
		}
		conn.Close()
		return
	}

	// Apply SessionTimeout as an absolute deadline for the connection.
	_ = conn.SetDeadline(time.Now().Add(time.Duration(srv.SessionTimeout) * time.Second))

	// Add artificial latency: 92% chance of 43-108ms, 8% chance of 60-160ms.
	delay := time.Duration(rand.IntN(65)+43) * time.Millisecond
	if rand.Float32() < 0.08 {
		delay = time.Duration(rand.IntN(100)+60) * time.Millisecond
	}
	time.Sleep(delay)

	// Display configured banner to client.
	if srv.Banner != "" {
		_, _ = conn.Write([]byte(srv.Banner))
	}

	// Display configured prompts to the client and record the responses.
	scanner := bufio.NewScanner(conn)
	responses := make(map[string]string, len(srv.Prompts))
	for i, prompt := range srv.Prompts {
		_, _ = conn.Write([]byte(prompt.Text))
		scanner.Scan()
		var key string
		// Each prompt includes an optional Log field that serves as the key
		// for logging. If Log is set to "none", the prompt is displayed, but
		// the response will not be logged. If Log is omitted, the default key
		// "data00" is used, where "00" is the index plus one.
		if prompt.Log == "none" {
			continue
		} else if prompt.Log != "" {
			key = prompt.Log
		} else {
			key = fmt.Sprintf("data%02d", i+1)
		}
		responses[key] = scanner.Text()

		// Add artificial latency between prompts (6-18ms).
		time.Sleep(time.Duration(rand.IntN(12)+6) * time.Millisecond)
	}

	// If no prompts are configured, wait for client input and record the
	// received data.
	if len(srv.Prompts) == 0 {
		scanner.Scan()
		responses["data"] = scanner.Text()
	}

	// Check if the client sent any data. If not, exit without logging.
	didProvideData := false
	for _, v := range responses {
		if v != "" {
			didProvideData = true
			break
		}
	}
	if !didProvideData {
		return
	}

	// Log and report the interaction.
	if srv.LogInteractions {
		srv.Logger.LogAttrs(context.Background(), slog.LevelInfo, "tcp", append(logData, slog.Any("event_details", responses))...)
		console.Debug(console.TCP, "%s → %q", evt.SourceIP, responsesToString(responses))
	}
	if srv.ReportInteractions {
		threatfeed.Update(evt.SourceIP)
	}
}

// preparelog builds structured log fields from network connection metadata.
func prepareLog(evt *eventdata.Connection, srv *config.Server) []slog.Attr {
	d := make([]slog.Attr, 0, 8)
	d = append(d,
		slog.Any("source_ip", evt.SourceIP),
	)
	if srv.UseProxyProtocol {
		d = append(d,
			slog.Bool("source_ip_parsed", evt.ProxyParsed),
			slog.String("source_ip_error", evt.ProxyError),
			slog.Any("proxy_ip", evt.ProxyIP),
		)
	}
	d = append(d,
		slog.Any("server_ip", evt.ServerIP),
		slog.String("server_port", strconv.FormatUint(uint64(evt.ServerPort), 10)),
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
