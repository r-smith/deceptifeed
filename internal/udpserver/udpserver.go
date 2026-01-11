package udpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/r-smith/deceptifeed/internal/config"
)

// Start launches a passive UDP honeypot that listens on the specified port. It
// records incoming packet data, but does not respond. The server is invisible
// to network scanners.
//
// Because UDP is connectionless and prone to IP spoofing, source IP addresses
// are considered unreliable. For this reason, the UDP server does not
// integrate with the threatfeed.
func Start(srv *config.Server) {
	fmt.Printf("Starting UDP server on port: %s\n", srv.Port)
	addr, err := net.ResolveUDPAddr("udp", ":"+srv.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "The UDP server on port %s has stopped: %v\n", srv.Port, err)
		return
	}

	// Start the UDP server.
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "The UDP server on port %s has stopped: %v\n", srv.Port, err)
		return
	}
	defer conn.Close()

	// Store the server's local IP and port.
	_, srvPort, _ := net.SplitHostPort(conn.LocalAddr().String())
	srvIP := config.GetHostIP()

	// Reusable buffer to store incoming data.
	buf := make([]byte, 1024)

	// Listen for and capture incoming UDP packets.
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		// UDP packet received. Capture the data and source IP address.
		capturedData := string(buf[:n])
		srcIP, _, _ := net.SplitHostPort(remoteAddr.String())

		// Log the received data. Because the source IP may be spoofed, an
		// "[unreliable]" tag is added.
		go func(data string, ip string) {
			srv.Logger.LogAttrs(context.Background(), slog.LevelInfo, "udp",
				slog.String("source_ip", ip+" [unreliable]"),
				slog.String("source_reliability", "unreliable"),
				slog.String("server_ip", srvIP),
				slog.String("server_port", srvPort),
				slog.String("server_name", config.Hostname),
				slog.Group("event_details",
					slog.String("data", data),
				),
			)

			// Print to the console.
			fmt.Printf("[UDP] %s Data: %q\n", ip, strings.TrimSpace(data))
		}(capturedData, srcIP)
	}
}
