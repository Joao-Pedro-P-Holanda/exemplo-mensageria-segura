package key_exchange

type KeyExchangeRequest struct {
	ClientId string `json:"clientId,omitempty"`
	Content  string `json:"content"`
}
