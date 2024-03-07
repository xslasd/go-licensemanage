package manage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
)

var ActivationCodeFileErr = errors.New("ActivationCodeFileErr")

const pwdbit = 10

func (m manage) encrypt(plainText []byte, publicKey []byte) ([]byte, error) {
	password := RandomPassword()
	block, _ := pem.Decode(publicKey)
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	passwordEncrypt, err := rsa.EncryptOAEP(m.h, rand.Reader, pub, password, nil)
	if err != nil {
		return nil, err
	}
	pwdLen := len(passwordEncrypt)
	//AESEncrypt
	ciphertext, err := AESEncrypt(plainText, password)
	if err != nil {
		return nil, err
	}
	iByte := intToBytes(pwdLen, pwdbit)
	res := append(iByte, passwordEncrypt...)
	res = append(res, ciphertext...)
	return res, nil
}
func (m manage) decrypt(cipherByte []byte, privateKey []byte) ([]byte, error) {
	if len(cipherByte) < pwdbit {
		return nil, ActivationCodeFileErr
	}
	pwdLenByte := cipherByte[:pwdbit]
	pwdLen := bytesToInt(pwdLenByte)
	if len(cipherByte) < pwdbit+pwdLen {
		return nil, ActivationCodeFileErr
	}
	passwordEncrypt := cipherByte[pwdbit : pwdLen+pwdbit]
	ciphertext := cipherByte[pwdbit+pwdLen:]
	block, _ := pem.Decode(privateKey)
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	password, err := rsa.DecryptOAEP(m.h, rand.Reader, pri, passwordEncrypt, nil)
	if err != nil {
		return nil, err
	}
	decrypted, err := AESDecrypt(ciphertext, password)
	if err != nil {
		return nil, err
	}
	return decrypted, err
}

func RandomPassword() []byte {
	randomPasswords := make([]byte, 16)
	rand.Read(randomPasswords)
	return randomPasswords
}

func intToBytes(n int, length int) []byte {
	bytes := make([]byte, length)
	binary.BigEndian.PutUint64(bytes, uint64(n))
	return bytes
}
func bytesToInt(bytes []byte) int {
	return int(binary.BigEndian.Uint64(bytes))
}

// AESEncrypt encryption
func AESEncrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()

	// pkcs7Padding
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	encryptBytes := append(data, padText...)

	crypted := make([]byte, len(encryptBytes))
	//cbc
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	blockMode.CryptBlocks(crypted, encryptBytes)
	return crypted, nil
}

// AESDecrypt Decrypt
func AESDecrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	//cbc
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	crypted := make([]byte, len(data))
	blockMode.CryptBlocks(crypted, data)

	//pkcs7UnPadding
	length := len(crypted)
	unPadding := int(crypted[length-1])
	crypted = crypted[:(length - unPadding)]
	return crypted, nil
}
