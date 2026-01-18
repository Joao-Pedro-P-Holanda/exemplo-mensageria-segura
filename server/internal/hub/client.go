package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"mensageria_segura/internal/database"
	"mensageria_segura/internal/key_exchange"

	"github.com/gorilla/websocket"
)

type Client struct {
	id           string
	ctx          context.Context
	conn         *websocket.Conn
	send         chan []byte
	sessionID    int
	symmetricKey []byte
	onMessage    func(client *Client, recipientID string, payload []byte)
	onClose      func(*Client)
}

func NewClient(
	id string,
	ctx context.Context,
	conn *websocket.Conn,
	sessionID int,
	onMessage func(client *Client, recipientID string, payload []byte),
	onClose func(client *Client),
) *Client {
	return &Client{
		id:        id,
		ctx:       ctx,
		conn:      conn,
		sessionID: sessionID,
		send:      make(chan []byte, 256),
		onMessage: onMessage,
		onClose:   onClose,
	}
}

func (c *Client) SessionID() int {
	return c.sessionID
}

func (c *Client) ID() string {
	return c.id
}

func (c *Client) ReadPump() {
	defer func() {
		if c.onClose != nil {
			c.onClose(c)
		}
		err := c.conn.Close()
		if err != nil {
			slog.Error("failed to close websocket connection", "error", err)
			return
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			_, message, err := c.conn.ReadMessage()
			if err != nil {
				if c.ctx.Err() != nil {
					return
				}
				if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
					slog.Info("websocket connection closed normally")
					return
				}

				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					slog.Error("websocket error", "error", err)
				}
				return
			}

			var encryptedMsg EncryptedMessage
			if err := json.Unmarshal(message, &encryptedMsg); err != nil {
				slog.Warn("invalid websocket payload", "error", err)
				continue
			}

			if encryptedMsg.Content == "" || encryptedMsg.IV == "" {
				slog.Warn("dropping unencrypted message; handshake likely not completed")
				continue
			}

			if encryptedMsg.SessionID != c.sessionID {
				slog.Warn("dropping message for another session", "session_id", encryptedMsg.SessionID)
				continue
			}

			// Find session using generic repository
			session, err := database.FindByID[database.Session](c.ctx, uint(encryptedMsg.SessionID))
			if err != nil {
				slog.Warn("unknown session id", "session_id", encryptedMsg.SessionID, "error", err)
				continue
			}

			if c.symmetricKey == nil {
				c.symmetricKey = session.EphemeralAESKey
			}

			plaintext, err := key_exchange.DecryptWithSymmetric(c.symmetricKey, encryptedMsg.Content, encryptedMsg.IV)
			if err != nil {
				slog.Error("failed to decrypt message", "error", err)
				continue
			}

			if c.onMessage != nil {
				c.onMessage(c, encryptedMsg.RecipientID, plaintext)
			}
		}
	}
}

func (c *Client) WritePump() {
	defer func(conn *websocket.Conn) {
		err := conn.Close()
		if err != nil {
			slog.Error("failed to close websocket connection", "error", err)
		}
	}(c.conn)

	for {
		select {
		case <-c.ctx.Done():
			return
		case message, ok := <-c.send:
			if !ok {
				return
			}
			err := c.conn.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				return
			}
		}
	}
}

func (c *Client) Send(msg []byte) {
	select {
	case <-c.ctx.Done():
		return
	case c.send <- msg:
	}
}

func (c *Client) Close() {
	close(c.send)
}

func (c *Client) IsAuthenticated() bool {
	return c.symmetricKey != nil
}
