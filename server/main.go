package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"mensageria_segura/internal/database"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lmittmann/tint"
	"github.com/rs/cors"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// WARNING: This allows all origins for development/testing purposes.
		// In production, restrict this to specific allowed origins for security.
		return true
	},
}

func (s *SessionStore) Set(id int, key []byte) {
	s.mutex.Lock()
	s.keys[id] = key
	s.mutex.Unlock()
}

func (s *SessionStore) Get(id int) ([]byte, bool) {
	s.mutex.RLock()
	key, ok := s.keys[id]
	s.mutex.RUnlock()
	return key, ok
}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan EncryptedMessage),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			h.clients[client] = true
			h.mutex.Unlock()
			slog.Info("Client connected", "total_clients", len(h.clients))

		case client := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mutex.Unlock()
			slog.Info("Client disconnected", "total_clients", len(h.clients))

		case encrypted := <-h.broadcast:
			h.mutex.Lock()
			for client := range h.clients {
				if client.symmetricKey == nil {
					continue
				}

				outgoing := encrypted
				frame, err := json.Marshal(outgoing)
				if err != nil {
					slog.Error("failed to marshal encrypted broadcast", "error", err)
					continue
				}

				select {
				// TODO: send as JSON instead of string to be parsed on client
				case client.send <- frame:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mutex.Unlock()
		}
	}
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Error("websocket error", "error", err)
			}
			break
		}
		var encryptedMsg EncryptedMessage
		if err := json.Unmarshal(message, &encryptedMsg); err != nil {
			slog.Warn("invalid websocket payload", "error", err)
			continue
		}

		// If payload is missing, this is likely an unencrypted message (e.g. client missed handshake). Ignore but do not spam logs.
		if encryptedMsg.Content == "" || encryptedMsg.IV == "" {
			slog.Warn("dropping unencrypted message; handshake likely not completed")
			continue
		}

		_, symKey, ok, _ := database.GetSession(database.DB, encryptedMsg.SessionID)
		if !ok {
			slog.Warn("unknown session id", "session_id", encryptedMsg.SessionID)
			continue
		}

		if c.sessionID == "" {
			c.symmetricKey = symKey
		}

		// TODO: send message only to the chat members
		c.hub.broadcast <- encryptedMsg
	}
}

func (c *Client) writePump() {
	defer c.conn.Close()

	for message := range c.send {
		err := c.conn.WriteMessage(websocket.TextMessage, message)
		if err != nil {
			return
		}
	}
}

func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("upgrade failed", "error", err)
		return
	}

	client := &Client{hub: hub, conn: conn, send: make(chan []byte, 256)}
	client.hub.register <- client

	// Start goroutines for reading and writing
	go client.writePump()
	go client.readPump()
}

func main() {
	// Initialize beautiful logging with colors and full date
	logger := slog.New(tint.NewHandler(os.Stdout, &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: "2006-01-02 15:04:05",
		NoColor:    false, // Explicitly enable colors
	}))
	slog.SetDefault(logger)

	if _, err := database.InitInMemory(); err != nil {
		slog.Error("failed to initialize database", "error", err)
		os.Exit(1)
	}

	hub := newHub()
	go hub.run()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})

	mux.HandleFunc("/key-exchange", KeyExchangeHandler)

	port := ":8080"
	handler := cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3001",
			"http://localhost:3002",
			"http://localhost:3003",
			"http://localhost:9000",
		},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type"},
	}).Handler(mux)

	server := &http.Server{
		Addr:         port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Server run context
	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	// Listen for syscall signals for process to interrupt/quit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sig

		// Shutdown signal with grace period of 30 seconds
		shutdownCtx, _ := context.WithTimeout(serverCtx, 30*time.Second)

		go func() {
			<-shutdownCtx.Done()
			if shutdownCtx.Err() == context.DeadlineExceeded {
				slog.Error("graceful shutdown timed out.. forcing exit.")
				os.Exit(1)
			}
		}()

		// Trigger graceful shutdown
		slog.Info("Shutting down server...")
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			slog.Error("server shutdown failed", "error", err)
			os.Exit(1)
		}
		serverStopCtx()
	}()

	slog.Info("WebSocket server starting", "port", port)
	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}

	// Wait for server context to be stopped
	<-serverCtx.Done()
	slog.Info("Server stopped gracefully")
}
