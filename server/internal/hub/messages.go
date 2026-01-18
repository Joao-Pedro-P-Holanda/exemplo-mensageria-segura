package hub

type EncryptedMessage struct {
	SessionID   int    `json:"sessionId"`
	SenderID    string `json:"senderId"`
	RecipientID string `json:"recipientId"`
	Content     string `json:"content"`
	IV          string `json:"iv"`
}

type ChatMessage struct {
	Username string `json:"username"`
	Content  string `json:"content"`
}
