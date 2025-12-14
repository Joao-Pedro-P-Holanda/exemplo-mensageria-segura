package main

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
	return x509.ParsePKCS1PrivateKey(certificateKey.Bytes)
}
