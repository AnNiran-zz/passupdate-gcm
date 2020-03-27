package crypt

// Encrypt starts the encryption process
func Encrypt() error {
	// Access plaintext data
	plaintext, err := readEncData(plaintxtFilename)
	if err != nil {
		return err
	}

	// Access encryption key file
	passphrase, err := readEncData(passwdFilename)
	if err != nil {
		return err
	}

	encryptionSrc := &encryptionData{
		// Create MD5 128-bit hash of the passphrase
		key:       md5Sum(passphrase),
		plaintext: plaintext,
	}

	data, err := encryptAes128gcm(encryptionSrc)
	if err != nil {
		return err
	}

	// Save data to a file - update content of existing 
	// `payload` file
	if err = record(ciphertextFilename, data.ciphertext); err != nil {
		return err
	}

	// Save nonce to a file - update content of existing `nonce` file
	if err = record(nonceFilename, data.nonce); err != nil {
		return err
	}

	return nil
}