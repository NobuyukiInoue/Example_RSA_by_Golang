package rwkeys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"unsafe"

	"golang.org/x/crypto/ssh"
	//	"golang.org/x/crypto/ssh"
)

//	"golang.org/x/crypto/ssh/keys"
// Install)
// $ go get golang.org/x/crypto/ssh

// golang : RSA キーを含む pem ファイルの読み込み
// http://increment.hatenablog.com/entry/2017/08/25/223915

// GetKeyType ...
func GetKeyType(pemFile string) (string, error) {
	keyType := ""
	bytes, err := ioutil.ReadFile(pemFile)
	if err != nil {
		return keyType, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return "", errors.New("invalid private key data")
	}

	if strings.Contains(block.Type, "PRIVATE") {
		keyType = "PRIVATE"
	} else if strings.Contains(block.Type, "PUBLIC") {
		keyType = "PUBLIC"
	}

	return keyType, nil
}

// ReadRsaPrivateKey ...
func ReadRsaPrivateKey(pemFile string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(pemFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("invalid private key data")
	}

	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	} else if block.Type == "PRIVATE KEY" {
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not RSA private key")
		}
		/*
			} else if block.Type == "OPENSSH PRIVATE KEY" {
				passPhrase := os.Getenv("PASSPHRASE")
				singer, err := ssh.ParseRawPrivateKeyWithPassphrase(block.Bytes, []byte(passPhrase))
				if err != nil {
					return nil, err
				}
				return singer, nil
		*/
	} else {
		return nil, fmt.Errorf("invalid private key type : %s", block.Type)
	}

	key.Precompute()

	if err := key.Validate(); err != nil {
		return nil, err
	}

	return key, nil
}

// ReadOpenSSHPrivateKey ...
func ReadOpenSSHPrivateKey(pemFile string) (*ssh.Signer, error) {
	bytes, err := ioutil.ReadFile(pemFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("invalid private key data")
	}

	var signer ssh.Signer
	if block.Type == "OPENSSH PRIVATE KEY" {
		//	passPhrase := os.Getenv("")
		passPhrase := ""
		//		signer, err = ssh.ParsePrivateKeyWithPassphrase(block.Bytes, []byte(passPhrase))
		signer, err = ssh.ParsePrivateKeyWithPassphrase(block.Bytes, *(*[]byte)(unsafe.Pointer(&passPhrase)))
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("invalid private key type : %s", block.Type)
	}

	return &signer, nil
}

// ReadRsaPublicKey ...
func ReadRsaPublicKey(path string) (*rsa.PublicKey, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("invalid public key data")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid public key type : %s", block.Type)
	}

	keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	key, ok := keyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	return key, nil
}
