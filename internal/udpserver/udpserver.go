package udpserver

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/console"
)

// Start launches a passive UDP honeypot that listens on the specified port. It
// records incoming packet data, but does not respond. The server is invisible
// to network scanners.
//
// Because UDP is connectionless and prone to IP spoofing, source IP addresses
// are considered unreliable. For this reason, the UDP server does not
// integrate with the threatfeed.
func Start(srv *config.Server) {
	addr, err := net.ResolveUDPAddr("udp", ":"+srv.Port)
	if err != nil {
		console.Error(console.UDP, "Failed to start honeypot on port %s: %v", srv.Port, err)
		return
	}

	// Start the UDP server.
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		console.Error(console.UDP, "Failed to start honeypot on port %s: %v", srv.Port, err)
		return
	}
	defer conn.Close()
	console.Info(console.UDP, "Honeypot is active and listening on port %s", srv.Port)

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
		var srcIP netip.Addr
		if addr, ok := remoteAddr.(*net.UDPAddr); ok {
			srcIP = addr.AddrPort().Addr().Unmap()
		}

		// Log the received data. Because the source IP may be spoofed, an
		// "[unreliable]" tag is added.
		go func(data string, ip netip.Addr) {
			srv.Logger.LogAttrs(context.Background(), slog.LevelInfo, "udp",
				slog.String("source_ip", ip.String()+" [unreliable]"),
				slog.String("source_reliability", "unreliable"),
				slog.String("server_ip", srvIP),
				slog.String("server_port", srvPort),
				slog.String("server_name", config.Hostname),
				slog.Group("event_details",
					slog.String("data", data),
				),
			)

			// Print to the console.
			console.Debug(console.UDP, "%s → %q", ip, strings.TrimSpace(data))
		}(capturedData, srcIP)
	}
}
