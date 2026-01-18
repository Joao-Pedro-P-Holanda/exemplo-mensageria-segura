package hub

import (
	"context"
	"encoding/json"
	"log/slog"
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
	inBox      chan MessageEvent
	register   chan *Client
	unregister chan *Client
	mutex      sync.RWMutex
}

func NewHub(ctx context.Context) *Hub {
	return &Hub{
		ctx:        ctx,
		inBox:      make(chan MessageEvent),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[string]*Client),
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
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.clients[client.ID()] = client
	slog.Info("Client connected", "total_clients", len(h.clients))
}

func (h *Hub) unregisterClient(client *Client) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if _, ok := h.clients[client.ID()]; ok {
		delete(h.clients, client.ID())
		client.Close()
	}
	slog.Info("Client disconnected", "total_clients", len(h.clients))
}

func (h *Hub) dispatchMessage(msg MessageEvent) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

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

	ciphertext, iv, err := key_exchange.EncryptWithSymmetric(client.symmetricKey, msg.Payload)
	if err != nil {
		slog.Error("failed to encrypt message for client", "error", err)
		return
	}

	// Re-construct the message structure expected by the client
	response := EncryptedMessage{
		SessionID:   client.SessionID(),
		RecipientID: msg.RecipientID,
		SenderID:    msg.SenderID,
		Content:     ciphertext,
		IV:          iv,
	}
	// Note: app.js uses sessionId in line 64 of handshake (data.sessionId).
	// In htmx:wsAfterMessage (line 191), it parses event.detail.message.
	// app.js line 195: decryptWithAesGcm(symmetricKey, incoming.content, incoming.iv)
	// It doesn't use sessionId from the incoming message.

	frame, err := json.Marshal(response)
	if err != nil {
		slog.Error("failed to marshal encrypted inBox", "error", err)
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
