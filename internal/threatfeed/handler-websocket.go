package threatfeed

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/websocket"
)

// maxRecentMessages is the maximum number of recent log messages to store.
const maxRecentMessages = 100

var (
	// muWSClients is to ensure threat-safe access to wsClients.
	muWSClients sync.Mutex

	// wsClients holds the connected WebSocket clients and is used to broadcast
	// messages to all clients.
	wsClients = make(map[*websocket.Conn]bool)

	// wsRecentMessages stores the most recent log messages. These messages
	// are sent to clients when they first connect.
	wsRecentMessages = make([]string, 0, maxRecentMessages*1.5)
)

// handleLiveIndex serves a web page that displays honeypot log data in
// real-time through a WebSocket connection.
func handleLiveIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(templates, "templates/live.html"))
	_ = tmpl.Execute(w, nil)
}

// broadcastLogsToClients receives honeypot log data through a byte channel
// configured to monitor the logs. When log data is received, the data is
// sent to all connected WebSocket clients. It also stores recent log data in a
// cache for newly connected clients.
func broadcastLogsToClients() {
	for msg := range cfg.Monitor.Channel {
		wsRecentMessages = append(wsRecentMessages, string(msg))
		if len(wsRecentMessages) > maxRecentMessages {
			wsRecentMessages = wsRecentMessages[1:]
		}

		muWSClients.Lock()
		for client := range wsClients {
			_ = websocket.Message.Send(client, string(msg))
		}
		muWSClients.Unlock()
	}
}

// handleWebSocket establishes and maintains WebSocket connections with clients
// and performs cleanup when clients disconnect.
func handleWebSocket(ws *websocket.Conn) {
	defer func() {
		muWSClients.Lock()
		delete(wsClients, ws)
		muWSClients.Unlock()
		ws.Close()
	}()

	// Enforce private IPs.
	ip, _, err := net.SplitHostPort(ws.Request().RemoteAddr)
	if err != nil {
		return
	}
	if netIP := net.ParseIP(ip); !netIP.IsPrivate() && !netIP.IsLoopback() {
		return
	}
	fmt.Println("[Threat Feed]", ip, "established WebSocket connection")

	// Add newly connected client to map.
	muWSClients.Lock()
	wsClients[ws] = true
	muWSClients.Unlock()

	// Send the cache of recent log messages to the new client.
	for _, msg := range wsRecentMessages {
		websocket.Message.Send(ws, msg)
	}
	// Send a message informing the client that we're done sending the initial
	// cache of log messages.
	websocket.Message.Send(ws, "---end---")

	// Keep WebSocket open.
	var message string
	for {
		err := websocket.Message.Receive(ws, &message)
		if err != nil {
			break
		}
	}
}
