package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"mensageria_segura/internal/key_exchange"
	"sync"
)

type MessageEvent struct {
	Sender  *Client
	Payload []byte
}

type Hub struct {
	ctx        context.Context
	clients    map[*Client]struct{}
	broadcast  chan MessageEvent
	register   chan *Client
	unregister chan *Client
	mutex      sync.RWMutex
}

func NewHub(ctx context.Context) *Hub {
	return &Hub{
		ctx:        ctx,
		broadcast:  make(chan MessageEvent),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]struct{}),
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
		case msg := <-h.broadcast:
			h.broadcastMessage(msg)
		}
	}
}

func (h *Hub) registerClient(client *Client) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.clients[client] = struct{}{}
	slog.Info("Client connected", "total_clients", len(h.clients))
}

func (h *Hub) unregisterClient(client *Client) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
		client.Close()
	}
	slog.Info("Client disconnected", "total_clients", len(h.clients))
}

func (h *Hub) broadcastMessage(msg MessageEvent) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	for client := range h.clients {
		// Skip the sender (Echo issue)
		if client == msg.Sender {
			continue
		}

		if !client.IsAuthenticated() {
			continue
		}

		ciphertext, iv, err := key_exchange.EncryptWithSymmetric(client.symmetricKey, msg.Payload)
		if err != nil {
			slog.Error("failed to encrypt message for client", "error", err)
			continue
		}

		// Re-construct the message structure expected by the client
		response := EncryptedMessage{
			SessionID: 0, // Not needed strictly for client-side display, or use client.sessionID? app.js doesn't seem to use sessionId heavily for display, just IV and Content.
			Content:   ciphertext,
			IV:        iv,
		}
		// Note: app.js uses sessionId in line 64 of handshake (data.sessionId).
		// In htmx:wsAfterMessage (line 191), it parses event.detail.message.
		// app.js line 195: decryptWithAesGcm(symmetricKey, incoming.content, incoming.iv)
		// It doesn't use sessionId from the incoming message.

		frame, err := json.Marshal(response)
		if err != nil {
			slog.Error("failed to marshal encrypted broadcast", "error", err)
			continue
		}

		client.Send(frame)
	}
}

func (h *Hub) Register(client *Client) {
	h.register <- client
}

func (h *Hub) Unregister(client *Client) {
	h.unregister <- client
}

func (h *Hub) Broadcast(sender *Client, payload []byte) {
	h.broadcast <- MessageEvent{
		Sender:  sender,
		Payload: payload,
	}
}
