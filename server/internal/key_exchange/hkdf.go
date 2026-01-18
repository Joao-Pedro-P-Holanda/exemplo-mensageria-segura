package key_exchange

import (
	"crypto/hkdf"
	"crypto/sha256"
)

func HKDFDeriveKeys(
	sharedSecret []byte,
	salt []byte,
) (keyC2S, keyS2C []byte, err error) {

	// HKDF-Extract
	prk, err := hkdf.Extract(sha256.New, sharedSecret, salt)
	if err != nil {
		return nil, nil, err
	}

	keyC2S, err = hkdf.Expand(sha256.New, prk, "c2s", 16)
	if err != nil {
		return nil, nil, err
	}

	keyS2C, err = hkdf.Expand(sha256.New, prk, "s2c", 16)
	if err != nil {
		return nil, nil, err
	}

	return keyC2S, keyS2C, nil
}
