package threatfeed

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"golang.org/x/net/websocket"
)

// maxRecentMessages is the maximum number of recent log messages to store.
const maxRecentMessages = 100

// wsClient represents a single WebSocket client with a dedicated channel.
type wsClient struct {
	conn *websocket.Conn
	send chan string
}

var (
	// wsMu protects access to wsClient and wsRecentMessages.
	wsMu sync.Mutex

	// wsClients holds the connected WebSocket clients.
	wsClients = make(map[*wsClient]struct{})

	// wsRecentMessages stores the most recent log messages.
	wsRecentMessages = make([]string, 0, maxRecentMessages*1.5)
)

// handleLiveIndex serves a web page that displays honeypot log data in
// real-time through a WebSocket connection.
func handleLiveIndex(w http.ResponseWriter, r *http.Request) {
	_ = parsedTemplates.ExecuteTemplate(w, "live.html", "live")
}

// broadcastLogsToClients receives honeypot log data through a byte channel
// configured to monitor the logs. When log data is received, the data is
// sent to all connected WebSocket clients. It also stores recent log data in a
// cache for newly connected clients.
func broadcastLogsToClients() {
	var clientsBuf []*wsClient

	for msg := range cfg.Monitor.Channel {
		m := string(msg)

		wsMu.Lock()
		// Update recent message cache.
		wsRecentMessages = append(wsRecentMessages, m)
		if len(wsRecentMessages) > maxRecentMessages {
			wsRecentMessages = wsRecentMessages[1:]
		}

		// Add clients to buffer (first reset it, but keep the capacity).
		clientsBuf = clientsBuf[:0]
		for c := range wsClients {
			clientsBuf = append(clientsBuf, c)
		}
		wsMu.Unlock()

		// Broadcast to clients.
		for _, c := range clientsBuf {
			select {
			case c.send <- m:
			default:
				// Drop messages for slow clients.
			}
		}
	}
}

// handleWebSocket establishes and maintains WebSocket connections.
func handleWebSocket(ws *websocket.Conn) {
	// Restrict access to private and link-local IP addresses.
	host, _, err := net.SplitHostPort(ws.Request().RemoteAddr)
	if err != nil {
		_ = ws.Close()
		return
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || (!addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast()) {
		_ = ws.Close()
		return
	}

	// Initialize client.
	client := &wsClient{
		conn: ws,
		send: make(chan string, 32),
	}

	// Register client and copy current message cache.
	wsMu.Lock()
	wsClients[client] = struct{}{}
	count := len(wsClients)
	recent := append([]string(nil), wsRecentMessages...)
	wsMu.Unlock()
	fmt.Printf("[THREATFEED] %s established websocket connection (total: %d)\n", host, count)

	// Ensure cleanup.
	defer func() {
		wsMu.Lock()
		delete(wsClients, client)
		count = len(wsClients)
		wsMu.Unlock()
		_ = ws.Close()
		fmt.Printf("[THREATFEED] %s closed websocket connection (total: %d)\n", host, count)
	}()

	// Goroutine to send messages to clients. Read from the 'send' channel and
	// push to the WebSocket.
	go func() {
		for msg := range client.send {
			if err := websocket.Message.Send(client.conn, msg); err != nil {
				// Stop goroutine if send fails.
				return
			}
		}
	}()

	// Push initial cached messages.
	for _, msg := range recent {
		client.send <- msg
	}
	client.send <- "---end---"

	// Block here to keep connection alive / wait for client to disconnect.
	var message string
	for {
		if err := websocket.Message.Receive(ws, &message); err != nil {
			// Connection lost or closed.
			break
		}
	}
}
