// Package server — WebSocket hub using the gorilla/websocket library.
//
// Architecture:
//
//	Hub
//	 ├── register   chan *Client   — new connection joins
//	 ├── unregister chan *Client   — connection closes
//	 └── broadcast  chan wsMessage — JSON payload to push to clients
//
//	Client
//	 ├── readPump   goroutine — reads client text (handles "ping" → "pong")
//	 └── writePump  goroutine — drains s.send channel to the WebSocket
//
// Session scoping:
//
//	If a Client has a non-nil sessionID, it only receives events that
//	share that sessionID.  A nil sessionID receives everything.
//
// On connect, the last 100 events are replayed to the new client.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/model"
)

// WebSocket tuning constants.
const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 512
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	// Allow all origins — CORS is handled at the HTTP layer.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// ── Hub ───────────────────────────────────────────────────────────────────────

// wsMessage is an internal broadcast request.
type wsMessage struct {
	payload   []byte   // pre-serialised JSON
	sessionID *string  // nil = send to all clients
}

// Hub maintains the registry of connected WebSocket clients and distributes
// broadcast messages.
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan wsMessage
	register   chan *Client
	unregister chan *Client
}

// NewHub allocates a Hub.  Call hub.Run() in a goroutine before use.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan wsMessage, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Run is the Hub's event loop.  It must run in its own goroutine.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
			slog.Debug("ws: client connected", "total", len(h.clients))

		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
				slog.Debug("ws: client disconnected", "total", len(h.clients))
			}

		case msg := <-h.broadcast:
			for client := range h.clients {
				// Session scoping: skip if the event and client sessions don't match.
				if msg.sessionID != nil && client.sessionID != nil &&
					*msg.sessionID != *client.sessionID {
					continue
				}

				select {
				case client.send <- msg.payload:
				default:
					// Slow client — drop and disconnect.
					delete(h.clients, client)
					close(client.send)
				}
			}
		}
	}
}

// BroadcastEvent serialises a SecurityEvent and pushes it to all matching clients.
func (h *Hub) BroadcastEvent(event *model.SecurityEvent) {
	payload, err := json.Marshal(map[string]any{
		"type":  "new_event",
		"event": event.Flatten(),
	})
	if err != nil {
		slog.Error("ws: marshal event", "err", err)
		return
	}
	h.broadcast <- wsMessage{payload: payload, sessionID: event.ExecveEvent.SessionID}
}

// BroadcastRaw pushes a raw JSON payload to all clients (used for system notifications).
func (h *Hub) BroadcastRaw(payload []byte) {
	h.broadcast <- wsMessage{payload: payload, sessionID: nil}
}

// ── Client ────────────────────────────────────────────────────────────────────

// Client is one connected WebSocket peer.
type Client struct {
	hub       *Hub
	conn      *websocket.Conn
	send      chan []byte
	sessionID *string
}

// readPump reads messages from the WebSocket.
// Only "ping" text messages are handled; everything else is ignored.
// Runs in its own goroutine; closes the connection when done.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait)) //nolint:errcheck
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait)) //nolint:errcheck
		return nil
	})

	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseGoingAway,
				websocket.CloseAbnormalClosure,
			) {
				slog.Debug("ws: unexpected close", "err", err)
			}
			break
		}

		// Python protocol: client sends "ping", server responds "pong".
		if string(msg) == "ping" {
			c.send <- []byte("pong")
		}
	}
}

// writePump drains the send channel and writes to the WebSocket connection.
// It also sends WebSocket-level ping frames on a timer.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait)) //nolint:errcheck
			if !ok {
				// Hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{}) //nolint:errcheck
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message) //nolint:errcheck

			// Batch any queued messages into this write.
			n := len(c.send)
			for range n {
				w.Write([]byte("\n")) //nolint:errcheck
				w.Write(<-c.send)    //nolint:errcheck
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait)) //nolint:errcheck
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
