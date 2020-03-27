package crypt

import (
	"errors"
	"fmt"
)

// encryption data object for holding extracted password and plaintext
// in bytes for using by the AES GCM encryption
type encryptionData struct {
	key       []byte
	nonce     []byte
	plaintext []byte
}

type decryptionData struct {
	key        []byte
	nonce      []byte
	ciphertext []byte
}

// Mode of operation
// `test` - decrypts, updates password and encrypts content in /rsc/test destination
// `standard` - decrypts, updates password and encrypts content in /rsc/standard destination
var Mode = "test"

// Errors
var ErrPathNonExistent = func (dest string) error {
	return fmt.Errorf("Destination path does not exist: %s", dest)
}

var (
	ErrCreateNonce = func(err string) error {
		return fmt.Errorf("Error creating nonce: %s", err)
	}

	ErrEncryption = func(err string) error {
		return fmt.Errorf("Encryption process error: %s", err)
	}

	ErrDecryption = func(err string) error {
		return fmt.Errorf("Decryption process error: %s", err)
	}

	ErrInvalidBlockSize = errors.New("Invalid blocksize")

	ErrNoCiphertextData = errors.New("No encrypted data has been extracted")
	ErrNoPassphraseData = errors.New("No passphrase data has been extracted")

	ErrNoSaltHeader     = errors.New("Data does not appear to be encrypted with OpenSSL, salt header missing")
	ErrInsufficientChipherData = func(size int) error {
		return fmt.Errorf("Ciphertext data is smaller than aes block size: %i", size)
	}
)

// Filepaths
// Encrypted resources paths
var EncSrcPath      = "encsrc"
var StandardEncrRrc = "standard"
var TestEncrPath    = "test"

var plaintxtFilename = "plaintext"
var passwdFilename   = "key"

var ciphertextFilename = "payload"
var nonceFilename      = "nonce"
