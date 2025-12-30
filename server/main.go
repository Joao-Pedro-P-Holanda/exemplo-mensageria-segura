package main

import (
	"encoding/json"
	"fmt"
	"log"
	"mensageria_segura/internal/database"
	"net/http"

	"github.com/gorilla/websocket"
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

var sessionStore = &SessionStore{keys: make(map[int][]byte)}

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
			log.Printf("Client connected. Total clients: %d", len(h.clients))

		case client := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mutex.Unlock()
			log.Printf("Client disconnected. Total clients: %d", len(h.clients))

		case encrypted := <-h.broadcast:
			h.mutex.Lock()
			for client := range h.clients {
				if client.symmetricKey == nil {
					continue
				}

				outgoing := encrypted
				frame, err := json.Marshal(outgoing)
				if err != nil {
					log.Printf("failed to marshal encrypted broadcast: %v", err)
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
				log.Printf("error: %v", err)
			}
			break
		}
		var encryptedMsg EncryptedMessage
		if err := json.Unmarshal(message, &encryptedMsg); err != nil {
			log.Printf("invalid websocket payload: %v", err)
			continue
		}

		// If payload is missing, this is likely an unencrypted message (e.g. client missed handshake). Ignore but do not spam logs.
		if encryptedMsg.Content == "" || encryptedMsg.IV == "" {
			log.Printf("dropping unencrypted message of type; handshake likely not completed")
			continue
		}

		_, symKey, ok, _ := database.GetSession(database.DB, encryptedMsg.SessionID)
		if !ok {
			log.Printf("unknown session id: %d", encryptedMsg.SessionID)
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
		log.Println(err)
		return
	}

	client := &Client{hub: hub, conn: conn, send: make(chan []byte, 256)}
	client.hub.register <- client

	// Start goroutines for reading and writing
	go client.writePump()
	go client.readPump()
}

func main() {
	if _, err := database.InitInMemory(); err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}

	hub := newHub()
	go hub.run()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})

	mux.HandleFunc("/key-exchange", KeyExchangeHandler)

	port := ":8080"
	fmt.Printf("WebSocket server starting on port %s\n", port)

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

	log.Fatal(http.ListenAndServe(port, handler))
}
