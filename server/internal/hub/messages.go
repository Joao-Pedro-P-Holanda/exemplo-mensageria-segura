package hub

type EncryptedMessage struct {
	SessionID int    `json:"sessionId"`
	Content   string `json:"content"`
	IV        string `json:"iv"`
}

type ChatMessage struct {
	Username string `json:"username"`
	Content  string `json:"content"`
}
