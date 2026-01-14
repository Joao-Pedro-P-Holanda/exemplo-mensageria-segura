package key_exchange

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// GenerateECDHKeyPair generates an ECDH key pair using P-256 curve (to match client)
func GenerateECDHKeyPair() (*ecdh.PrivateKey, error) {
	curve := ecdh.P256()
	return curve.GenerateKey(rand.Reader)
}

func ConvertJWKToECDHPublic(jwkBytes []byte) (*ecdh.PublicKey, error) {
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(jwkBytes); err != nil {
		return nil, fmt.Errorf("failed to parse jwk: %w", err)
	}
	if !jwk.IsPublic() {
		return nil, fmt.Errorf("jwk is not a public key")
	}

	switch k := jwk.Key.(type) {
	case *ecdh.PublicKey:
		return k, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("unsupported curve: %T", k.Curve)
		}
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		x := k.X.Bytes()
		y := k.Y.Bytes()
		if len(x) > byteLen || len(y) > byteLen {
			return nil, fmt.Errorf("invalid coordinate length")
		}
		encoded := make([]byte, 1+2*byteLen)
		encoded[0] = 4 // uncompressed form indicator
		copy(encoded[1+byteLen-len(x):1+byteLen], x)
		copy(encoded[1+2*byteLen-len(y):], y)
		pub, err := ecdh.P256().NewPublicKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("failed to build ecdh public key: %w", err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", jwk.Key)
	}
}

func ConvertJWKToECDHPrivate(jwkBytes []byte) (*ecdh.PrivateKey, error) {
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(jwkBytes); err != nil {
		return nil, fmt.Errorf("failed to parse jwk: %w", err)
	}
	if jwk.IsPublic() {
		return nil, fmt.Errorf("jwk does not contain a private key")
	}

	switch k := jwk.Key.(type) {
	case *ecdh.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("unsupported curve: %T", k.Curve)
		}
		dBytes := k.D.Bytes()
		if len(dBytes) > 32 {
			return nil, fmt.Errorf("invalid private key size: %d", len(dBytes))
		}
		padded := make([]byte, 32)
		copy(padded[32-len(dBytes):], dBytes)

		priv, err := ecdh.P256().NewPrivateKey(padded)
		if err != nil {
			return nil, fmt.Errorf("failed to build ecdh private key: %w", err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", jwk.Key)
	}
}

func DeriveSharedSecret(serverPriv *ecdh.PrivateKey, clientPub *ecdh.PublicKey) ([]byte, error) {
	secret, _ := serverPriv.ECDH(clientPub)

	if secret == nil {
		return nil, errors.New("failed to derive shared secret")
	}

	// Ensure 32-byte output
	if len(secret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(secret):], secret)
		secret = padded
	}

	return secret, nil
}

func DeriveSymmetricKey(sharedSecret []byte, salt []byte) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(salt); err != nil {
		return nil, fmt.Errorf("failed to hash salt: %w", err)
	}
	if _, err := h.Write(sharedSecret); err != nil {
		return nil, fmt.Errorf("failed to hash secret: %w", err)
	}
	return h.Sum(nil), nil
}

func EncryptWithSymmetric(key []byte, plaintext []byte) (string, string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("failed to init gcm: %w", err)
	}

	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", "", fmt.Errorf("failed to create iv: %w", err)
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(iv), nil
}

func DecryptWithSymmetric(key []byte, ciphertextB64 string, ivB64 string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to init gcm: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}
	iv, err := base64.StdEncoding.DecodeString(ivB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode iv: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt using symmetric key: %w", err)
	}

	return plaintext, nil
}

// CreateKeyExchangeResponse creates a signed key exchange response
func CreateKeyExchangeResponse(
	serverPublicKeyJWK map[string]any,
	salt string,
) ([]byte, error) {

	payload := map[string]any{
		"serverPublicKey": serverPublicKeyJWK,
		"salt":            salt,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	signature, err := SignDataWithRSA(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	response := map[string]any{
		"serverPublicKey": serverPublicKeyJWK,
		"salt":            salt,
		"signature":       signature,
	}

	return json.Marshal(response)
}

func GenerateSalt(length int) (string, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}
