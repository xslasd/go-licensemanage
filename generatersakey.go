package manage

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type RSAKeyModel struct {
	ClientActivationEncryptKey []byte
	ClientLicenseDecryptKey    []byte

	ManageActivationDecryptKey []byte
	ManageLicenseEncryptKey    []byte
}

func GenerateRSAKey() (RSAKeyModel, error) {
	private1, public1 := generatePEMKey()
	private2, public2 := generatePEMKey()
	return RSAKeyModel{
		ClientActivationEncryptKey: public1,
		ClientLicenseDecryptKey:    private2,

		ManageActivationDecryptKey: private1,
		ManageLicenseEncryptKey:    public2,
	}, nil
}

func generatePEMKey() (private []byte, public []byte) {
	// Generate a 2048-bit RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	// Obtain private key
	// Encode the private key in PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	// Obtain public key
	publicKey := &privateKey.PublicKey

	// Encode public key in PEM format
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	})
	return privateKeyPEM, publicKeyPEM
}
