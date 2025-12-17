package main

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

var serverCurve = ecdh.X25519()

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

/*
Generates a public ephemeral key signed with the RSA private key
*/
func GenerateEphemeralKey() ([]byte, error) {

	certificateKey, err := readCertificateKey("key.pem")
	if err != nil {
		return nil, err
	}

	privateKey, err := serverCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	publickKey := privateKey.PublicKey()

	return rsa.SignPKCS1v15(rand.Reader, certificateKey, crypto.SHA256, publickKey.Bytes())
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
