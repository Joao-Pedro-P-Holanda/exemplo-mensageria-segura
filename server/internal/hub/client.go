package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"mensageria_segura/internal/database"

	"github.com/gorilla/websocket"
)

type Client struct {
	ctx          context.Context
	conn         *websocket.Conn
	send         chan []byte
	sessionID    string
	symmetricKey []byte
	onMessage    func(EncryptedMessage)
	onClose      func()
}

func NewClient(ctx context.Context, conn *websocket.Conn, onMessage func(EncryptedMessage), onClose func()) *Client {
	return &Client{
		ctx:       ctx,
		conn:      conn,
		send:      make(chan []byte, 256),
		onMessage: onMessage,
		onClose:   onClose,
	}
}

func (c *Client) ReadPump() {
	defer func() {
		if c.onClose != nil {
			c.onClose()
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
				// If the loop is ending due to context cancellation, don't log it as an error.
				if c.ctx.Err() != nil {
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

			_, symKey, ok, _ := database.GetSession(database.DB, encryptedMsg.SessionID)
			if !ok {
				slog.Warn("unknown session id", "session_id", encryptedMsg.SessionID)
				continue
			}

			if c.symmetricKey == nil {
				c.symmetricKey = symKey
			}

			if c.onMessage != nil {
				c.onMessage(encryptedMsg)
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
	case c.send <- msg:
	default:
		c.Close()
	}
}

func (c *Client) Close() {
	close(c.send)
}

func (c *Client) IsAuthenticated() bool {
	return c.symmetricKey != nil
}
