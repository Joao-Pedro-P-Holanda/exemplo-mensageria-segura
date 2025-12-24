package internal

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

/*
Verifies if the data received was signed with the public certificate
*/
func DecryptWithPrivateCertificate(base64Content string) ([]byte, error) {
	privateKey, err := ReadCertificateKey("key.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	decodedText, _ := base64.StdEncoding.DecodeString(base64Content)

	decryptedData, err := rsa.DecryptOAEP(sha256.New(), nil, privateKey, decodedText, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with server private key: %w", err)
	}
	return decryptedData, nil
}

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
		return nil, fmt.Errorf("Certificate isn't a valid RSA key %v", err)
	}
	return privateKey.(*rsa.PrivateKey), nil
}
