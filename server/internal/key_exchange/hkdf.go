package key_exchange

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// HKDFDeriveKeys derives two keys (keyC2S and keyS2C) using HKDF with the provided shared secret and salt.
// sharedSecret is the input keying material (IKM) for derivation.
// Salt is the optional HKDF salt, which can provide additional randomness to the key derivation process.
// Returns keyC2S (key for client-to-server communication) and keyS2C (key for server-to-client communication).
// Returns an error if the derivation process fails at any step.
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
