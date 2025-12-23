package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"sync"

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

type Client struct {
	conn         *websocket.Conn
	send         chan []byte
	hub          *Hub
	sessionID    string
	symmetricKey []byte
}

type Message struct {
	Username string `json:"username"`
	Content  string `json:"content"`
	Type     string `json:"type"` // "chat", "join", "leave", "key-exchange"
}

type EncryptedMessage struct {
	SessionID string `json:"sessionId"`
	Payload   string `json:"payload"`
	IV        string `json:"iv"`
	Type      string `json:"type"`
}

type KeyExchangeRequest struct {
	PublicKey map[string]interface{} `json:"publicKey"`
}

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan Message
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

type SessionStore struct {
	mutex sync.RWMutex
	keys  map[string][]byte
}

func (s *SessionStore) Set(id string, key []byte) {
	s.mutex.Lock()
	s.keys[id] = key
	s.mutex.Unlock()
}

func (s *SessionStore) Get(id string) ([]byte, bool) {
	s.mutex.RLock()
	key, ok := s.keys[id]
	s.mutex.RUnlock()
	return key, ok
}

var sessionStore = &SessionStore{keys: make(map[string][]byte)}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan Message),
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
				if client.symmetricKey == nil {
					continue
				}

				payload, err := json.Marshal(message)
				if err != nil {
					log.Printf("failed to marshal broadcast payload: %v", err)
					continue
				}

				ciphertext, iv, err := EncryptWithSymmetric(client.symmetricKey, payload)
				if err != nil {
					log.Printf("failed to encrypt broadcast for client: %v", err)
					continue
				}

				outgoing := EncryptedMessage{Type: "encrypted-chat", Payload: ciphertext, IV: iv}
				frame, err := json.Marshal(outgoing)
				if err != nil {
					log.Printf("failed to marshal encrypted broadcast: %v", err)
					continue
				}

				select {
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
		if encryptedMsg.Payload == "" || encryptedMsg.IV == "" {
			log.Printf("dropping unencrypted message of type %s; handshake likely not completed", encryptedMsg.Type)
			continue
		}

		if encryptedMsg.Type != "encrypted-chat" {
			log.Printf("unsupported message type: %s", encryptedMsg.Type)
			continue
		}

		symKey, ok := sessionStore.Get(encryptedMsg.SessionID)
		if !ok {
			log.Printf("unknown session id: %s", encryptedMsg.SessionID)
			continue
		}

		plaintext, err := DecryptWithSymmetric(symKey, encryptedMsg.Payload, encryptedMsg.IV)
		if err != nil {
			log.Printf("failed to decrypt payload: %v", err)
			continue
		}

		var msg Message
		if err := json.Unmarshal(plaintext, &msg); err != nil {
			log.Printf("failed to unmarshal decrypted message: %v", err)
			continue
		}

		if msg.Type == "" {
			msg.Type = "chat"
		}

		if c.sessionID == "" {
			c.sessionID = encryptedMsg.SessionID
			c.symmetricKey = symKey
		}

		c.hub.broadcast <- msg
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

func keyExchangeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	defer r.Body.Close()
	var req KeyExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	serverPriv, err := GenerateECDHKeyPair()
	if err != nil {
		log.Printf("failed to generate server key pair: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate server keys"})
		return
	}

	serverPubJWK, err := ExportPublicKeyToJWK(&serverPriv.PublicKey)
	if err != nil {
		log.Printf("failed to export server public key: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to export public key"})
		return
	}

	sharedSecret, err := DeriveSharedSecret(serverPriv, req.PublicKey)
	if err != nil {
		log.Printf("failed to derive shared secret: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid client public key"})
		return
	}

	salt, err := GenerateSalt(32)
	if err != nil {
		log.Printf("failed to generate salt: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate salt"})
		return
	}

	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		log.Printf("failed to decode salt: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to handle salt"})
		return
	}

	symmetricKey, err := DeriveSymmetricKey(sharedSecret, saltBytes)
	if err != nil {
		log.Printf("failed to derive symmetric key: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to derive key"})
		return
	}

	sessionID, err := generateSessionID()
	if err != nil {
		log.Printf("failed to generate session id: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create session"})
		return
	}

	sessionStore.Set(sessionID, symmetricKey)

	responseJSON, err := CreateKeyExchangeResponse(serverPubJWK, salt)
	if err != nil {
		log.Printf("failed to sign exchange: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to build response"})
		return
	}

	var response map[string]interface{}
	if err := json.Unmarshal(responseJSON, &response); err != nil {
		log.Printf("failed to unmarshal signed response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to finalize response"})
		return
	}

	response["sessionId"] = sessionID

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func convertMessageToHTML(msg Message) string {
	escapedUsername := html.EscapeString(msg.Username)
	escapedContent := html.EscapeString(msg.Content)

	if msg.Type == "join" || msg.Type == "leave" {
		return fmt.Sprintf(`<div class="message system" hx-swap-oob="beforeend:#messages">
			<div class="message-content">%s</div>
		</div>`, escapedContent)
	}

	return fmt.Sprintf(`<div class="message" hx-swap-oob="beforeend:#messages">
		<div class="message-header">
			<strong>%s</strong>
		</div>
		<div class="message-content">%s</div>
	</div>`, escapedUsername, escapedContent)
}

func main() {
	hub := newHub()
	go hub.run()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/verify", verifyHandler)
	mux.HandleFunc("/key-exchange", keyExchangeHandler)

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
