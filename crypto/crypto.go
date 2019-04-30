package crypto


import (
	"crypto/rsa"
	"encoding/pem"
	"io/ioutil"
	"github.com/pkg/errors"
	jwt "github.com/dgrijalva/jwt-go"
)


func LoadPrivBytes(keyfile string) ([]byte, error) {
	bKeyFile, err := ioutil.ReadFile(keyfile)
	if err != nil {
		err = errors.Wrap(err, "failed to read keyfile in LoadPrivRSA")
		return nil, err
	}
        block , _ := pem.Decode(bKeyFile)
	var bKey []byte = block.Bytes
	return bKey, err
}


func LoadPrivRSA(keyfile string) (*rsa.PrivateKey, error) {
	bKeyFile, err := ioutil.ReadFile(keyfile)
	if err != nil {
		err = errors.Wrap(err, "failed to read keyfile in LoadPrivRSA")
		return nil, err
	}
	rsaPriv, err := jwt.ParseRSAPrivateKeyFromPEM(bKeyFile)
	if err != nil {
		err = errors.Wrap(err, "failed to parsa RSA from key file bytes in LoadPrivRSA")
		return nil, err
	}
	return rsaPriv, err
}



