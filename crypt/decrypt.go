package crypt

// Decrypt handles data access and all corresponding errors from utility functions,
// calls decryption functionality and writes encrypted data to files if successful
func Decrypt() error {
	// Access encrypted data - payload
	ciphtxtRaw, err := readEncData(ciphertextFilename)
	if err != nil {
		return err
	}
	
	// Access key
	passRaw, err := readEncData(passwdFilename)
	if err != nil {
		return err
	}

	// Access nonce
	nonceRaw, err := readEncData(nonceFilename)
	if err != nil {
		return err
	}
	
	// password is 128-bit MD5 hash of the passphrase + 16 empty bytes
	//passphrase, err := getPassword(passRaw)
	//if err != nil {
	//	return err
	//}

	decryptionSrc := &decryptionData {
		// Create MD5 128-bit hash of the passphrase
		key:        passRaw,
		nonce:      nonceRaw,
		ciphertext: ciphtxtRaw,
	}
	
	// Decrypt data using the password
	decrypted, err := decryptAes128gcm(decryptionSrc)
	if err != nil {
		return ErrDecryption(err.Error())
	}

	// Save plaintext data to file
	if err = record(plaintxtFilename, decrypted.plaintext); err != nil {
		return err
	}
		
	return nil
}
