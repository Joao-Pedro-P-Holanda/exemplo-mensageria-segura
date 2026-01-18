package main

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mensageria_segura/internal"
	"mensageria_segura/internal/database"
	"mensageria_segura/internal/hub"
	"mensageria_segura/internal/key_exchange"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Controller struct {
	ctx context.Context
	hub *hub.Hub
}

func NewController(ctx context.Context, h *hub.Hub) *Controller {
	return &Controller{
		ctx: ctx,
		hub: h,
	}
}

func (c *Controller) HandleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("upgrade failed", "error", err)
		return
	}

	client := hub.NewClient(
		c.ctx,
		conn,
		c.hub.Broadcast,
		c.hub.Unregister,
	)

	c.hub.Register(client)

	// Start goroutines for reading and writing
	go client.WritePump()
	go client.ReadPump()
}

func (c *Controller) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to write json response", "error", err)
	}
}

func (c *Controller) writeError(w http.ResponseWriter, status int, message string, err error) {
	if err != nil {
		slog.Error(message, "error", err)
	}
	c.writeJSON(w, status, map[string]string{"error": message})
}

func (c *Controller) HandleKeyExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		c.writeError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slog.Error("failed to close request body", "error", err)
		}
	}(r.Body)
	var req key_exchange.KeyExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.writeError(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	response, err := c.conductKeyExchange(req)
	if err != nil {
		// Individual errors are already logged in conductKeyExchange
		c.writeError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	c.writeJSON(w, http.StatusOK, response)
}

func (c *Controller) conductKeyExchange(req key_exchange.KeyExchangeRequest) (map[string]any, error) {
	decryptedJWKBytes, err := internal.DecryptWithPrivateCertificate(req.Content)
	if err != nil {
		slog.Error("could not decrypt client public jwk", "error", err)
		return nil, fmt.Errorf("invalid encrypted content")
	}

	clientPub, err := key_exchange.ConvertJWKToECDHPublic(decryptedJWKBytes)
	if err != nil {
		slog.Error("failed to parse client jwk as ecdh", "error", err)
		return nil, fmt.Errorf("invalid client public key")
	}

	serverPrivy, err := key_exchange.GenerateECDHKeyPair()
	if err != nil {
		slog.Error("failed to generate server key pair", "error", err)
		return nil, fmt.Errorf("failed to generate server keys")
	}

	serverPubJWKMap, err := ecdhPublicKeyToJWKMap(serverPrivy.PublicKey())
	if err != nil {
		slog.Error("failed to encode server public key jwk", "error", err)
		return nil, fmt.Errorf("failed to prepare public key")
	}

	sharedSecret, err := key_exchange.DeriveSharedSecret(serverPrivy, clientPub)
	if err != nil {
		slog.Error("failed to derive shared secret", "error", err)
		return nil, fmt.Errorf("invalid client public key")
	}

	salt, err := key_exchange.GenerateSalt(32)
	if err != nil {
		slog.Error("failed to generate salt", "error", err)
		return nil, fmt.Errorf("failed to generate salt")
	}

	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		slog.Error("failed to decode salt", "error", err)
		return nil, fmt.Errorf("failed to handle salt")
	}

	symmetricKey, err := key_exchange.DeriveSymmetricKey(sharedSecret, saltBytes)
	if err != nil {
		slog.Error("failed to derive symmetric key", "error", err)
		return nil, fmt.Errorf("failed to derive key")
	}

	sessionID, err := database.CreateSession(database.DB, req.ClientId, salt, symmetricKey)
	if err != nil {
		slog.Error("failed to generate session id", "error", err)
		return nil, fmt.Errorf("failed to create session")
	}

	payload := map[string]any{
		"serverPublicKey": serverPubJWKMap,
		"salt":            salt,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		slog.Error("failed to marshal payload", "error", err)
		return nil, fmt.Errorf("failed to prepare payload")
	}

	signature, err := internal.SignPayload(payloadBytes)
	if err != nil {
		slog.Error("failed to sign payload", "error", err)
		return nil, fmt.Errorf("failed to sign response")
	}

	return map[string]any{
		"payload":   base64.StdEncoding.EncodeToString(payloadBytes),
		"signature": base64.StdEncoding.EncodeToString(signature),
		"sessionId": sessionID,
	}, nil
}

func ecdhPublicKeyToJWKMap(pub *ecdh.PublicKey) (map[string]any, error) {
	// P-256 uncompressed point encoding: 0x04 || X(32) || Y(32)
	encoded := pub.Bytes()
	if len(encoded) != 65 || encoded[0] != 4 {
		return nil, fmt.Errorf("unexpected public key encoding: len=%d first=%d", len(encoded), encoded[0])
	}

	x := encoded[1:33]
	y := encoded[33:65]

	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
		"ext": true,
	}, nil
}
