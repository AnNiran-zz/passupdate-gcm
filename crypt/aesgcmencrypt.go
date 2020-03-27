package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// encryptAes128gcm encrypts data using the key with AES-128-GCM
func encryptAes128gcm(data *encryptionData) (*decryptionData, error) {
	// Use the MD5 hash used as a key
	b, err := aes.NewCipher(data.key)
	if err != nil {
		return nil, err
	}

	// Create nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrCreateNonce(err.Error())
	}

	// gcm is AEAD - a cipher mode providing authenticated encryption
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, ErrEncryption(err.Error())
	}

	ciphertext := gcm.Seal(nil, nonce, data.plaintext, nil)
	return &decryptionData{nonce: nonce, ciphertext: ciphertext}, nil
}
