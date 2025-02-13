package manage

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/google/uuid"
)

type LicenseLimitHandler func(activationInfo ActivationInfo, data *LicenseInfo) error

type ActivationDecryptFunc func(cipherByte []byte, privateKey []byte) ([]byte, error)
type LicenseEncryptFunc func(plainText []byte, publicKey []byte) ([]byte, error)

type manage struct {
	licenseLimitHandler LicenseLimitHandler
	pollVerifyTime      string

	activationDecryptFunc ActivationDecryptFunc
	licenseEncryptFunc    LicenseEncryptFunc
	h                     hash.Hash
}
type Option func(*manage)

func WithOAEPHash(h hash.Hash) Option {
	return func(config *manage) {
		config.h = h
	}
}

// WhitPollVerifyTime Set the automatic polling time for license verification, with a default of 24 hours.
// Please use ParseDuration parses a duration string.
func WithPollVerifyTime(pollVerifyTime string) Option {
	return func(config *manage) {
		config.pollVerifyTime = pollVerifyTime
	}
}

// WhitLicenseLimitHandler Add processors with license restrictions。
func WithLicenseLimitHandler(handler LicenseLimitHandler) Option {
	return func(config *manage) {
		config.licenseLimitHandler = handler
	}
}

func WithLicenseEncryptFunc(fn LicenseEncryptFunc) Option {
	return func(config *manage) {
		config.licenseEncryptFunc = fn
	}
}
func WithActivationDecryptFunc(fn ActivationDecryptFunc) Option {
	return func(config *manage) {
		config.activationDecryptFunc = fn
	}
}

type ActivationInfo struct {
	Subject          string         `json:"subject"`
	Description      string         `json:"description,omitempty"`
	InvitationCode   string         `json:"invitation_code"`
	ActivationChecks map[string]any `json:"activation_checks"`
}

type LicenseInfo struct {
	LicenseKey       string         `json:"license_key" form:"license_key"`
	Subject          string         `json:"subject"`
	Description      string         `json:"description,omitempty"`
	IssuedTime       int64          `json:"issued_time"`
	ExpiryTime       int64          `json:"expiry_time"`
	InvitationCode   string         `json:"invitation_code,omitempty"`
	PollVerifyTime   time.Duration  `json:"poll_verify_time"`
	ActivationChecks map[string]any `json:"activation_checks"`
}

type RSAKeyConfig struct {
	ActivationDecryptKey []byte
	LicenseEncryptKey    []byte
}

// GenerateLicense Generate License
// activationCode Activate the file [] byte. ExpiryTime is a millisecond timestamp, and when it is -1, it indicates that the license will never expire.
func GenerateLicense(rsaKey RSAKeyConfig, activationCode []byte, expiryTime int64, opts ...Option) ([]byte, error) {
	m := new(manage)
	for _, o := range opts {
		o(m)
	}
	if m.h == nil {
		m.h = sha1.New()
	}
	if m.licenseEncryptFunc == nil {
		m.licenseEncryptFunc = m.encrypt
	}
	if m.activationDecryptFunc == nil {
		m.activationDecryptFunc = m.decrypt
	}
	ActivationInfoByte, err := m.activationDecryptFunc(activationCode, rsaKey.ActivationDecryptKey)
	if err != nil {
		return nil, err
	}
	activationInfo := new(ActivationInfo)
	err = json.Unmarshal(ActivationInfoByte, activationInfo)
	if err != nil {
		return nil, err
	}
	duration, err := time.ParseDuration(m.pollVerifyTime)
	if err == nil {
		return nil, err
	}

	res := new(LicenseInfo)
	res.LicenseKey = strings.ReplaceAll(uuid.NewString(), "-", "")
	res.Subject = activationInfo.Subject
	res.Description = activationInfo.Description
	res.InvitationCode = activationInfo.InvitationCode
	res.IssuedTime = time.Now().UnixMilli()
	res.ExpiryTime = expiryTime
	res.PollVerifyTime = duration
	res.ActivationChecks = activationInfo.ActivationChecks
	if m.licenseLimitHandler != nil {
		err = m.licenseLimitHandler(*activationInfo, res)
		if err != nil {
			return nil, err
		}
	}
	data, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	resEncryptByte, err := m.licenseEncryptFunc(data, rsaKey.LicenseEncryptKey)
	if err != nil {
		return nil, err
	}
	fmt.Println("License generation successful!")
	fmt.Println("License ExpiryTime:", res.ExpiryTime)
	return resEncryptByte, nil
}
