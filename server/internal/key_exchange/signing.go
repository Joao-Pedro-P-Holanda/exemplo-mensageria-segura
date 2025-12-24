package key_exchange

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"mensageria_segura/internal"
)

// SignDataWithRSA signs data using RSA private key
func SignDataWithRSA(data []byte) (string, error) {
	certificateKey, err := internal.ReadCertificateKey("key.pem")
	if err != nil {
		return "", fmt.Errorf("failed to read certificate key: %w", err)
	}

	// Hash the data
	hashed := sha256.Sum256(data)

	// Sign with RSA
	signature, err := rsa.SignPKCS1v15(rand.Reader, certificateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}
