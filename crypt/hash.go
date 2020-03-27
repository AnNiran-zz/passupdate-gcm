package crypt

import (
	"crypto/md5"
)

// md5Sum returns an MD5 sum of the provided resource
func md5Sum(data []byte) []byte {
	hash := md5.New()
	hash.Write(data)
	return hash.Sum(nil)
}
