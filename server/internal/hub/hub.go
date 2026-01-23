package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"mensageria_segura/internal/database"
	"mensageria_segura/internal/key_exchange"
	"sync"
)

type MessageEvent struct {
	SenderID    string
	RecipientID string
	Payload     []byte
}

type Hub struct {
	ctx        context.Context
	clients    map[string]*Client
	sessions   map[int]*Session
	inBox      chan MessageEvent
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

func NewHub(ctx context.Context) *Hub {
	return &Hub{
		ctx:        ctx,
		inBox:      make(chan MessageEvent),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[string]*Client),
		sessions:   make(map[int]*Session),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case <-h.ctx.Done():
			slog.Info("Hub shutting down")
			return
		case client := <-h.register:
			h.registerClient(client)
		case client := <-h.unregister:
			h.unregisterClient(client)
		case msg := <-h.inBox:
			h.dispatchMessage(msg)
		}
	}
}

func (h *Hub) registerClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[client.ID()] = client
	slog.Info("Client connected", "total_clients", len(h.clients))
}

func (h *Hub) unregisterClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[client.ID()]; ok {
		delete(h.clients, client.ID())
		defer client.Close()
	}
	slog.Info("Client disconnected", "total_clients", len(h.clients))
}

func (h *Hub) dispatchMessage(msg MessageEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if msg.RecipientID != "" {
		recipient, ok := h.clients[msg.RecipientID]
		if !ok {
			slog.Warn("recipient not found", "recipient_id", msg.RecipientID)
			return
		}
		h.encryptAndSendMessage(msg, recipient)
		return
	}

	for clientID, client := range h.clients {
		// Skip the sender (Echo issue)
		if clientID == msg.SenderID {
			continue
		}

		h.encryptAndSendMessage(msg, client)
	}
}

func (h *Hub) encryptAndSendMessage(msg MessageEvent, client *Client) {
	if !client.IsAuthenticated() {
		return
	}

	session, ok := h.GetSession(client.SessionID())
	if !ok {
		return
	}

	seq := session.NextSeq()

	aad := BuildAAD(
		msg.SenderID,
		msg.RecipientID,
		seq,
	)

	ciphertext, iv, err := key_exchange.EncryptWithSymmetricAAD(
		client.session.KeyS2C(),
		msg.Payload,
		aad,
	)
	if err != nil {
		slog.Error("failed to encrypt message for client", "error", err)
		return
	}

	// Re-construct the message structure expected by the client
	response := EncryptedMessage{
		SessionID:   client.SessionID(),
		RecipientID: msg.RecipientID,
		SenderID:    msg.SenderID,
		SeqNo:       seq,
		Content:     ciphertext,
		IV:          iv,
	}
	// Note: app.js uses sessionId in line 64 of handshake (data.sessionId).
	// In htmx:wsAfterMessage (line 191), it parses event.detail.message.
	// app.js line 195: decryptWithAesGcm(symmetricKey, incoming.content, incoming.iv)
	// It doesn't use sessionId from the incoming message.

	frame, err := json.Marshal(response)
	if err != nil {
		slog.Error("failed to marshal encrypted message", "error", err)
		return
	}

	client.Send(frame)
}

func (h *Hub) Register(client *Client) {
	h.register <- client
}

func (h *Hub) Unregister(client *Client) {
	h.unregister <- client
}

func (h *Hub) DeliverMessage(sender *Client, recipientID string, payload []byte) {

	h.inBox <- MessageEvent{
		SenderID:    sender.ID(),
		RecipientID: recipientID,
		Payload:     payload,
	}
}

func (h *Hub) GetSession(sessionID int) (*Session, bool) {
	h.mu.RLock()
	session, exists := h.sessions[sessionID]
	h.mu.RUnlock()

	if exists {
		return session, true
	}

	dto, err := database.FindByID[database.Session](h.ctx, uint(sessionID))
	if err != nil {
		return nil, false
	}

	session = NewSession(dto)

	h.mu.Lock()
	h.sessions[sessionID] = session
	h.mu.Unlock()

	return session, true
}

func (h *Hub) CreateSession(clientID string, salt string, keyC2S []byte, keyS2C []byte) (sessionID int, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	sessionDTO := &database.Session{
		ClientID: clientID,
		Salt:     salt,
		KeyC2S:   keyC2S,
		KeyS2C:   keyS2C,
	}
	err = database.Create(h.ctx, sessionDTO)
	if err != nil {
		return 0, err
	}

	session := NewSession(sessionDTO)

	h.sessions[session.ID()] = session

	return session.ID(), nil
}
