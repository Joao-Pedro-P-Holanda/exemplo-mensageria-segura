package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"mensageria_segura/internal"
	"mensageria_segura/internal/database"
	"mensageria_segura/internal/key_exchange"
	"net/http"
)

func ecdhPublicKeyToJWKMap(pub *ecdh.PublicKey) (map[string]any, error) {
	// P-256 uncompressed point encoding: 0x04 || X(32) || Y(32)
	encoded := pub.Bytes()
	if len(encoded) != 65 || encoded[0] != 4 {
		return nil, fmt.Errorf("unexpected public key encoding: len=%d first=%d", len(encoded), encoded[0])
	}

	x := encoded[1:33]
	y := encoded[33:65]

	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
		"ext": true,
	}, nil
}

// TODO: consider client_id, add message authentication with AEAD, seq_no and nonce
func KeyExchangeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	defer r.Body.Close()
	var req KeyExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	decryptedJWKBytes, err := internal.DecryptWithPrivateCertificate(req.Content)
	if err != nil {
		log.Printf("could not decrypt client public jwk %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid encrypted content"})
		return
	}

	clientPub, err := key_exchange.ConvertJWKToECDHPublic(decryptedJWKBytes)
	if err != nil {
		log.Printf("failed to parse client jwk as ecdh: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid client public key"})
		return
	}

	serverPriv, err := key_exchange.GenerateECDHKeyPair()
	if err != nil {
		log.Printf("failed to generate server key pair: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate server keys"})
		return
	}

	serverPubJWKMap, err := ecdhPublicKeyToJWKMap(serverPriv.PublicKey())
	if err != nil {
		log.Printf("failed to encode server public key jwk: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to prepare public key"})
		return
	}

	sharedSecret, err := key_exchange.DeriveSharedSecret(serverPriv, clientPub)
	if err != nil {
		log.Printf("failed to derive shared secret: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid client public key"})
		return
	}

	salt, err := key_exchange.GenerateSalt(32)
	if err != nil {
		log.Printf("failed to generate salt: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate salt"})
		return
	}

	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		log.Printf("failed to decode salt: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to handle salt"})
		return
	}

	symmetricKey, err := key_exchange.DeriveSymmetricKey(sharedSecret, saltBytes)
	if err != nil {
		log.Printf("failed to derive symmetric key: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to derive key"})
		return
	}

	sessionID, err := database.CreateSession(database.DB, req.ClientId, salt, symmetricKey)
	if err != nil {
		log.Printf("failed to generate session id: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create session"})
		return
	}

	responseJSON, err := key_exchange.CreateKeyExchangeResponse(serverPubJWKMap, salt)
	if err != nil {
		log.Printf("failed to sign exchange: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to build response"})
		return
	}

	var response map[string]any
	if err := json.Unmarshal(responseJSON, &response); err != nil {
		log.Printf("failed to unmarshal signed response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to finalize response"})
		return
	}

	response["sessionId"] = sessionID

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
