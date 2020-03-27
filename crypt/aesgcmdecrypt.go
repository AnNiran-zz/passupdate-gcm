package crypt

import (
	"crypto/aes"
	"crypto/cipher"
)

// decryptAes128gcm decrypts data using AES-128-GCM mode
func decryptAes128gcm(data *decryptionData) (*encryptionData, error) {
	keymd5 := md5Sum(data.key)

	block, err := aes.NewCipher(keymd5[:])
	if err != nil {
		return nil, ErrDecryption(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryption(err.Error())
	}

	plaintext, err := gcm.Open(nil, data.nonce, data.ciphertext, nil)
	if err != nil {
		return nil, ErrDecryption(err.Error())
	}

	return &encryptionData{
		plaintext: plaintext,
		nonce:     data.nonce,
		key:       data.key,
	}, nil

}
