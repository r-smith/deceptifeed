package udpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/r-smith/deceptifeed/internal/config"
)

// Start initializes and starts a generic UDP honeypot server. It listens on
// the specified port, logging any received data without responding back to the
// client. Since UDP is connectionless, clients are unaware of the server's
// existence and that it is actively listening and recording data sent to the
// port. Note that source IP addresses for UDP packets are unreliable due to
// potential spoofing. As a result, interactions with the UDP server are not
// added to the threat feed.
func Start(cfg *config.Server) {
	fmt.Printf("Starting UDP server on port: %s\n", cfg.Port)
	port, err := strconv.Atoi(cfg.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "The UDP server on port %s has stopped: %v\n", cfg.Port, err)
		return
	}

	// Start the UDP server.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		fmt.Fprintf(os.Stderr, "The UDP server on port %s has stopped: %v\n", cfg.Port, err)
		return
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
			// interaction and the received data. Because the source IP address
			// and port may be spoofed, an "[unreliable]" tag is added to both
			// the source IP and source port.
			//
			// Note:
			// Go's listenUDP does not capture the local IP address that
			// received the UDP packet. To assist with logging, call
			// config.GetHostIP(), which returns the first active local IP
			// address found on the system. On systems with multiple IP
			// addresses, this may not correspond to the IP address that
			// received the UDP data. However, this limitation is acceptable as
			// the primary goal is to log the received data.
			_, dstPort, _ := net.SplitHostPort(conn.LocalAddr().String())
			srcIP, _, _ := net.SplitHostPort(remoteAddr.String())
			cfg.Logger.LogAttrs(context.Background(), slog.LevelInfo, "",
				slog.String("event_type", "udp"),
				slog.String("source_ip", srcIP+" [unreliable]"),
				slog.String("source_reliability", "unreliable"),
				slog.String("server_ip", config.GetHostIP()),
				slog.String("server_port", dstPort),
				slog.String("server_name", config.GetHostname()),
				slog.Group("event_details",
					slog.String("data", string(buffer[:n])),
				),
			)

			// Print a simplified version of the interaction to the console.
			fmt.Printf("[UDP] %s Data: %q\n", srcIP, strings.TrimSpace(string(buffer[:n])))
		}()
	}
}
