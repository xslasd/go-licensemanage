package main

import (
	"flag"
	"fmt"
	manage "github.com/xslasd/go-licensemanage"
	"os"
	"strconv"
	"time"
)

const OnlineUsers_ItemKey = "online_Users"

func main() {
	var generateRSAKey bool
	flag.BoolVar(&generateRSAKey, "GenerateRSAKey", false, "Generate RSA Key")

	var activationCodeDir string
	var expiryTime int64
	var activationDecryptKeyDir string
	var licenseEncryptKeyDir string
	var onlineUsersLimit int64

	flag.StringVar(&activationCodeDir, "ActivationCodeDir", "../../client/example/activation_code.key", "Set activate file dir")
	flag.Int64Var(&expiryTime, "ExpiryTime", -1, "License expiration time, such as 20240130")
	flag.Int64Var(&onlineUsersLimit, "OnlineUsersLimit", -1, "Online user limit")
	flag.StringVar(&activationDecryptKeyDir, "ActivationDecryptKeyDir", "./.manage_key/activation_decrypt.pem", "Set decrypt activation private key file directory")
	flag.StringVar(&licenseEncryptKeyDir, "LicenseEncryptKeyDir", "./.manage_key/license_encrypt.pem", "Set encrypt license public key file directory")
	flag.Parse()
	if generateRSAKey {
		rsaKey, err := manage.GenerateRSAKey()
		if err != nil {
			panic(err)
		}
		err = os.MkdirAll(".client_key", os.ModeDir)
		if err != nil {
			panic(err)
		}
		err = os.MkdirAll(".manage_key", os.ModeDir)
		if err != nil {
			panic(err)
		}
		ClientActivationEncryptFile, err := os.Create("./.client_key/activation_encrypt.pem")
		if err != nil {
			panic(err)
		}
		ClientActivationEncryptFile.Write(rsaKey.ClientActivationEncryptKey)
		ClientActivationEncryptFile.Close()

		ClientLicenseDecryptFile, err := os.Create("./.client_key/license_decrypt.pem")
		if err != nil {
			panic(err)
		}
		ClientLicenseDecryptFile.Write(rsaKey.ClientLicenseDecryptKey)
		ClientLicenseDecryptFile.Close()

		ManageActivationDecryptFile, err := os.Create("./.manage_key/activation_decrypt.pem")
		if err != nil {
			panic(err)
		}
		ManageActivationDecryptFile.Write(rsaKey.ManageActivationDecryptKey)
		ManageActivationDecryptFile.Close()

		ManageLicenseEncryptFile, err := os.Create("./.manage_key/license_encrypt.pem")
		if err != nil {
			panic(err)
		}
		ManageLicenseEncryptFile.Write(rsaKey.ManageLicenseEncryptKey)
		ManageLicenseEncryptFile.Close()
		return
	}
	if activationCodeDir == "" {
		fmt.Println("Please use the activation Code Dir parameter to specify the activation file")
		return
	}

	activationDecryptkey, err := os.ReadFile(activationDecryptKeyDir)
	if err != nil {
		panic(err)
	}

	licenseEncryptkey, err := os.ReadFile(licenseEncryptKeyDir)
	if err != nil {
		panic(err)
	}

	activationCode, err := os.ReadFile(activationCodeDir)
	if err != nil {
		panic(err)
	}
	if expiryTime > -1 {
		t, err := time.Parse("20060102", strconv.FormatInt(expiryTime, 10))
		if err != nil {
			panic(err)
		}
		expiryTime = t.UnixMilli()
	}
	b, err := manage.GenerateLicense(
		manage.RSAKeyConfig{
			ActivationDecryptKey: activationDecryptkey,
			LicenseEncryptKey:    licenseEncryptkey,
		},
		activationCode,
		expiryTime,
		manage.WithLicenseLimitHandler(func(activationInfo manage.ActivationInfo, data *manage.LicenseInfo) error {
			fmt.Println(activationInfo)
			if onlineUsersLimit > 0 {
				data.ActivationChecks[OnlineUsers_ItemKey] = onlineUsersLimit
			}
			return nil
		}),
	)
	if err != nil {
		panic(err)
	}
	licenseFile, err := os.Create("license.key")
	if err != nil {
		panic(err)
	}
	licenseFile.Write(b)
	licenseFile.Close()
}
