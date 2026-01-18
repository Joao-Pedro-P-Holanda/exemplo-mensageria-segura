package key_exchange

type KeyExchangeRequest struct {
	ClientId *int   `json:"clientId,omitempty"`
	Content  string `json:"content"`
}
