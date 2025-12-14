package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// WARNING: This allows all origins for development/testing purposes.
		// In production, restrict this to specific allowed origins for security.
		return true
	},
}

type Client struct {
	conn *websocket.Conn
	send chan []byte
	hub  *Hub
}

type Message struct {
	Username string `json:"username"`
	Content  string `json:"content"`
	Type     string `json:"type"` // "chat", "join", "leave"
}

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mutex      sync.RWMutex
}

type VerifyRequest struct {
	EncryptedData string `json:"encryptedData"`
}

type VerifyResponse struct {
	Success       bool   `json:"success"`
	DecryptedData string `json:"decryptedData,omitempty"`
	Error         string `json:"error,omitempty"`
}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte),
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

		case message := <-h.broadcast:
			h.mutex.Lock()
			for client := range h.clients {
				select {
				case client.send <- message:
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

		// Broadcast the message to all clients
		c.hub.broadcast <- message
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

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(VerifyResponse{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(VerifyResponse{
			Success: false,
			Error:   "Error reading request body",
		})
		return
	}
	defer r.Body.Close()

	var req VerifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(VerifyResponse{
			Success: false,
			Error:   "Invalid JSON",
		})
		return
	}

	// Decode base64 encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(req.EncryptedData)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(VerifyResponse{
			Success: false,
			Error:   "Invalid base64 encoding",
		})
		return
	}

	// Try to decrypt
	decryptedData, err := DecryptData(encryptedData)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(VerifyResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to decrypt data: %v", err),
		})
		return
	}

	// Success - return 200
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(VerifyResponse{
		Success:       true,
		DecryptedData: string(decryptedData),
	})
	log.Printf("Successfully decrypted data: %s", string(decryptedData))
}

func main() {
	hub := newHub()
	go hub.run()

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	http.HandleFunc("/verify", verifyHandler)

	port := ":8080"
	fmt.Printf("WebSocket server starting on port %s\n", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
