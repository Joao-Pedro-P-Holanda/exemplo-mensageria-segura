package internal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

/*
Assina um payload usando a chave privada do certificado do servidor
*/
func SignPayload(payload []byte) ([]byte, error) {
	privateKey, err := ReadCertificateKey("key.pem")
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(payload)

	return rsa.SignPKCS1v15(
		rand.Reader,
		privateKey,
		crypto.SHA256,
		hash[:],
	)
}

/*
Decripta dados usando a chave privada do certificado
*/
func DecryptWithPrivateCertificate(base64Content string) ([]byte, error) {
	privateKey, err := ReadCertificateKey("key.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	decodedText, err := base64.StdEncoding.DecodeString(base64Content)
	if err != nil {
		return nil, err
	}

	decryptedData, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey,
		decodedText,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with server private key: %w", err)
	}

	return decryptedData, nil
}

/*
Lê a chave privada RSA do certificado PEM
*/
func ReadCertificateKey(filename string) (*rsa.PrivateKey, error) {
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
		return nil, fmt.Errorf("certificate isn't a valid RSA key: %v", err)
	}

	return privateKey.(*rsa.PrivateKey), nil
}
