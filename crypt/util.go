package crypt

import (
	"os"
	"path/filepath"
	"io/ioutil"
)

// readEncData access file inside /encsrc directory with the provided filename
// used to read data for encryption and decryption
func readEncData(filename string) ([]byte, error) {
	workPath, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	srcFile := filepath.Join(workPath, EncSrcPath, Mode, filename)
	if _, err := os.Stat(srcFile); os.IsNotExist(err) {
		return nil, ErrPathNonExistent(srcFile)
	}

	return ioutil.ReadFile(srcFile)
}

// record access a file and update its content
func record(filename string, value []byte) error {
	workPath, err := os.Getwd()
	if err != nil {
		return err
	}

	// Access file and replace content
	// we do not need to check if the file exists here because we do not depend 
	// on its content anymore
	// new file will be created if none exists
	file, err := os.OpenFile(filepath.Join(workPath, EncSrcPath, Mode, filename), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	if _, err = file.Write(value); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}

	return nil
}
