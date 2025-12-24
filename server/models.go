package main

import (
	"sync"

	"github.com/gorilla/websocket"
)

type Client struct {
	conn         *websocket.Conn
	send         chan []byte
	hub          *Hub
	sessionID    string
	symmetricKey []byte
}

type EncryptedMessage struct {
	SessionID string `json:"sessionId"`
	Content   string `json:"content"`
	IV        string `json:"iv"`
}

type ChatMessage struct {
	Username string `json:"username"`
	Content  string `json:"content"`
}

type KeyExchangeRequest struct {
	Content string `json:"content"`
}

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan EncryptedMessage
	register   chan *Client
	unregister chan *Client
	mutex      sync.RWMutex
}

type SessionStore struct {
	mutex sync.RWMutex
	keys  map[string][]byte
}

type JWK struct {
	x string
	y string
}
