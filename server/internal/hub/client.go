package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"mensageria_segura/internal/key_exchange"
	"sync"

	"github.com/gorilla/websocket"
)

type Client struct {
	id        string
	ctx       context.Context
	conn      *websocket.Conn
	send      chan []byte
	session   *Session
	onMessage func(client *Client, recipientID string, payload []byte)
	onClose   func(*Client)
	closeOnce sync.Once
}

func NewClient(
	id string,
	ctx context.Context,
	conn *websocket.Conn,
	session *Session,
	onMessage func(client *Client, recipientID string, payload []byte),
	onClose func(client *Client),
) *Client {
	return &Client{
		id:        id,
		ctx:       ctx,
		conn:      conn,
		session:   session,
		send:      make(chan []byte, 256),
		onMessage: onMessage,
		onClose:   onClose,
	}
}

func (c *Client) SessionID() int {
	return c.session.ID()
}

func (c *Client) ID() string {
	return c.id
}

func (c *Client) ReadPump() {
	defer c.closeConnection()

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

			if encryptedMsg.SessionID != c.session.ID() {
				slog.Warn("dropping message for another session",
					"session_id", encryptedMsg.SessionID,
					"expected_session_id", c.session.ID(),
					"client_id", c.ID(),
				)
				continue
			}

			seq := encryptedMsg.SeqNo
			if !c.session.AdvanceRecvSeq(seq) {
				slog.Warn("replay or out-of-order",
					"current", c.session.RecvSeq(),
					"incoming", seq,
				)
				continue
			}

			aad := BuildAAD(
				encryptedMsg.SenderID,
				encryptedMsg.RecipientID,
				seq,
			)

			plaintext, err := key_exchange.DecryptWithSymmetricAAD(c.session.KeyC2S(), encryptedMsg.Content, encryptedMsg.IV, aad)
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
	defer c.closeConnection()

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
	if c.session == nil {
		return false
	}
	c2s, s2c := c.session.KeyPair()
	return c2s != nil && s2c != nil
}

func (c *Client) closeConnection() {
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose(c)
		}
		err := c.conn.Close()
		if err != nil {
			slog.Error("failed to close websocket connection", "error", err)
		}
	})
}
