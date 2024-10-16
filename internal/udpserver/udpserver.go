package udpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/r-smith/cti-honeypot/internal/config"
)

// StartUDP serves as a wrapper to initialize and start a generic UDP honeypot
// server. It listens on the specified port, logging any received data without
// responding back to the client. Since UDP is connectionless, clients are
// unaware of the server's existence and that it is actively listening and
// recording data sent to the port. This function calls the underlying startUDP
// function to perform the actual server startup.
func StartUDP(cfg *config.Config, srv *config.Server) {
	fmt.Printf("Starting UDP server on port: %s\n", srv.Port)
	if err := startUDP(cfg, srv); err != nil {
		fmt.Fprintln(os.Stderr, "The UDP server has terminated:", err)
	}
}

// startUDP starts the UDP honeypot server. It handles the server's main loop
// and logging.
func startUDP(cfg *config.Config, srv *config.Server) error {
	// Convert the specified port number to an integer.
	port, err := strconv.Atoi(srv.Port)
	if err != nil {
		return fmt.Errorf("invalid port '%s': %w", srv.Port, err)
	}

	// Start the UDP server.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return fmt.Errorf("failure to listen on port '%s': %w", srv.Port, err)
	}
	defer conn.Close()

	// Listen for and accept incoming data, with a maximum size of 1024 bytes.
	buffer := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFrom(buffer)
		if err != nil {
			continue
		}

		go func() {
			// The UDP server has received incoming data from a client. Log the
			// interaction and the received data. Note: Go's listenUDP does not
			// capture the local IP address that received the UDP packet. To
			// assist with logging, call config.GetHostIP(), which returns the
			// first active local IP address found on the system. On systems
			// with multiple IP addresses, this may not correspond to the IP
			// address that received the UDP data. However, this limitation is
			// acceptable as the primary goal is to log the source IP and
			// received data.
			_, dst_port, _ := net.SplitHostPort(conn.LocalAddr().String())
			src_ip, src_port, _ := net.SplitHostPort(remoteAddr.String())
			cfg.Logger.LogAttrs(context.Background(), slog.LevelInfo, "",
				slog.String("event_type", "udp"),
				slog.String("source_ip", src_ip),
				slog.String("source_port", src_port),
				slog.String("sensor_ip", config.GetHostIP()),
				slog.String("sensor_port", dst_port),
				slog.String("sensor_name", config.GetHostname()),
				slog.Group("event_details",
					slog.String("data", string(buffer[:n])),
				),
			)

			// Print a simplified version of the interaction to the console.
			fmt.Printf("[UDP] %s Data: %s\n", src_ip, strings.TrimSpace(string(buffer[:n])))
		}()
	}
}
