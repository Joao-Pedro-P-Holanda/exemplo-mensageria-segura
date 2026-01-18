package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
)

type Hub struct {
	ctx        context.Context
	clients    map[*Client]struct{}
	broadcast  chan EncryptedMessage
	register   chan *Client
	unregister chan *Client
	mutex      sync.RWMutex
}

func NewHub(ctx context.Context) *Hub {
	return &Hub{
		ctx:        ctx,
		broadcast:  make(chan EncryptedMessage),
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

func (h *Hub) broadcastMessage(msg EncryptedMessage) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	for client := range h.clients {
		if !client.IsAuthenticated() {
			continue
		}

		frame, err := json.Marshal(msg)
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

func (h *Hub) Broadcast(msg EncryptedMessage) {
	h.broadcast <- msg
}
