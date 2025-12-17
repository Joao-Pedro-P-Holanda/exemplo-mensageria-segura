package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
)

/*
Verifies if the data received was signed with the public certificate
*/
func DecryptData(data []byte) ([]byte, error) {
	privateKey, err := readCertificateKey("key.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	return decryptedData, nil
}

func readCertificateKey(filename string) (*rsa.PrivateKey, error) {

	certKeyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate key file: %s", err)
	}
	certificateKey, _ := pem.Decode(certKeyBytes)
	if certificateKey == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(certificateKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Certificate isn't a valid RSA key")
	}
	return privateKey.(*rsa.PrivateKey), nil
}

// GenerateSalt creates a random salt of specified byte length
func GenerateSalt(length int) (string, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// GenerateECDHKeyPair generates an ECDH key pair using P-256 curve (to match client)
func GenerateECDHKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ExportPublicKeyToJWK exports ECDSA public key to JWK format (matching client expectations)
func ExportPublicKeyToJWK(pubKey *ecdsa.PublicKey) (map[string]interface{}, error) {
	// Encode coordinates to base64 URL encoding
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()

	// Pad to 32 bytes for P-256
	if len(xBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(xBytes):], xBytes)
		xBytes = padded
	}
	if len(yBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(yBytes):], yBytes)
		yBytes = padded
	}

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}

	return jwk, nil
}

func jwkToPublicKey(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	xRaw, okX := jwk["x"].(string)
	yRaw, okY := jwk["y"].(string)
	if !okX || !okY {
		return nil, errors.New("missing coordinates in JWK")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coord: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y coord: %w", err)
	}

	curve := elliptic.P256()
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("client public key not on curve")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func DeriveSharedSecret(serverPriv *ecdsa.PrivateKey, clientJWK map[string]interface{}) ([]byte, error) {
	clientPub, err := jwkToPublicKey(clientJWK)
	if err != nil {
		return nil, err
	}

	curve := elliptic.P256()
	sx, _ := curve.ScalarMult(clientPub.X, clientPub.Y, serverPriv.D.Bytes())
	if sx == nil {
		return nil, errors.New("failed to derive shared secret")
	}

	// Ensure 32-byte output
	secret := sx.Bytes()
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
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func generateSessionID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// SignDataWithRSA signs data using RSA private key
func SignDataWithRSA(data []byte) (string, error) {
	certificateKey, err := readCertificateKey("key.pem")
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

// CreateKeyExchangeResponse creates a signed key exchange response
func CreateKeyExchangeResponse(serverPublicKeyJWK map[string]interface{}, salt string) ([]byte, error) {
	// Create response structure
	response := map[string]interface{}{
		"serverPublicKey": serverPublicKeyJWK,
		"salt":            salt,
	}

	// Marshal to JSON
	responseJSON, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	// Sign the response
	signature, err := SignDataWithRSA(responseJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to sign response: %w", err)
	}

	// Add signature to response
	response["signature"] = signature

	// Marshal final response
	return json.Marshal(response)
}
