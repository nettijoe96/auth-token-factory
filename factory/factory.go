package factory

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/nettijoe96/auth-token-factory/crypto"
	"github.com/nettijoe96/auth-token-factory/lightning"
	"net/http"
        "io"
	"os"
	"strconv"
	"log"
	"time"
)


type JWTHandler struct {}


func (h JWTHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var peerCerts []*x509.Certificate = r.TLS.PeerCertificates
	var bClientPubKey []byte
        var xClientPubKey string
        p := lightning.GetGlobalPlugin()
	var ksToPsFile string = p.GetOptionValue("factory-trustedkeyfile")
	var keyfile string = p.GetOptionValue("keyfile")
	var err error
	var priv *rsa.PrivateKey
	priv, err = crypto.LoadPrivRSA(keyfile)
	if err != nil {
		log.Fatal(errors.Wrap(err, "failed to LoadPrivRSA in ServeHTTP"))
	}
	if len(peerCerts) == 1 {
		bClientPubKey, err = x509.MarshalPKIXPublicKey(peerCerts[0].PublicKey)
		if err != nil {
			log.Fatal(errors.Wrap(err, "failed to marshall public key in ServeHTTP"))
		}
		xClientPubKey = hex.EncodeToString(bClientPubKey)
	        f, err := os.Open(ksToPsFile)
		if err != nil {
			log.Fatal(errors.Wrap(err, "failed to open ksToPsFile in ServeHTTP"))
		}
	        var decoder *json.Decoder = json.NewDecoder(f)
	        var ksToPs lightning.KeysToPriviledges
	        decoder.Decode(&ksToPs)
	        defer f.Close()
                var priviledges []string = getPriviledges(xClientPubKey, ksToPs)
	        if priviledges != nil {
			token, err := createToken(priviledges, priv)
			if err != nil {
			        log.Fatal(errors.Wrap(err, "token failed to sign in createToken"))
			}
		        io.WriteString(w, token)
	        }else{
			w.WriteHeader(http.StatusUnauthorized)
	        }
	}else{
		w.WriteHeader(http.StatusUnauthorized)
	}

}

func getPriviledges(pubKey string, ksToPs lightning.KeysToPriviledges) []string {
	for _, kToPs := range ksToPs.KsToPs {
		if kToPs.PubKey == pubKey {
			return kToPs.Priviledges
		}
	}
	return nil
}

func createToken(priviledges []string, priv *rsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims {
		"priviledges": priviledges,
		"timestamp": strconv.FormatInt((time.Now().Unix()), 10),
	})
	tokenWithSig, err := token.SignedString(priv)
	if err != nil {
		errors.Wrap(err, "error signing token. Probablly due to inputted private key")
		return "", err
	}
	return tokenWithSig, err
}
