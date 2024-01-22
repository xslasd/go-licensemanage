# go-license(software license)
go-license is a project written in Go language for generating and validating software license files. It can be integrated into your software as a license validation framework.
# Features
* You can customize the addition of verification processing methods. Such as binding IP, MAC, etc.
* Using RSA and AES encryption to activate and license content.
* Less dependence, unique acquisition of computer identification. github.com/shirou/gopsutil/v3
# How to use
This project is divided into two parts：go-licensecli and go-licensemanage
### go-licensecli
go-licensecli Used for integration into the program. Main functions: generate activation files, verify license files.

client Main implementation interfaces
```go
type LicenseCli interface {
	GenerateActivationCode(opts ...GenerateOption) ([]byte, error)
	ActivateLicense(licenseCode []byte) (bool, error)
	VerifyLicense() (bool, error)
	GetLicenseInfo() (*LicenseInfo, error)
}
```
Specific View: https://github.com/xslasd/go-license.

### go-licensemanage
go-licensemanage Used for managing licenses. Main functions: parsing activation files and generating license files.
```go
  GenerateLicense(rsaKey RSAKeyConfig, activationCode []byte, expiryTime int64, opts ...Option) ([]byte, error)
  GenerateRSAKey() (RSAKeyModel, error)
```
Specific View: https://github.com/xslasd/go-licensemanage

