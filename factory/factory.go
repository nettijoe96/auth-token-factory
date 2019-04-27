package factory

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/nettijoe96/auth-token-factory/crypto"
	"github.com/nettijoe96/auth-token-factory/lightning"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

func CreateJWTHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	        var peerCerts []*x509.Certificate = r.TLS.PeerCertificates
	        var bClientPubKey []byte
		var xClientPubKey string
		p := lightning.GetGlobalPlugin()
	        var ksToPsFile string = p.GetOptionValue("factory-trustedkeyfile")
	        var keyfile string = p.GetOptionValue("keyfile")
		var priv []byte = crypto.LoadPrivBytes(keyfile)
	        if len(peerCerts) == 1 {
		        //grab pub key
		        bClientPubKey = peerCerts[0].PublicKey.([]byte)
			xClientPubKey = hex.Dump(bClientPubKey)
	                f, _ := os.Open(ksToPsFile)
	                //TODO err check
	                var decoder *json.Decoder = json.NewDecoder(f)
	                var ksToPs lightning.KeysToPriviledges
	                decoder.Decode(&ksToPs)
	                defer f.Close()
			var priviledges []string = getPriviledges(xClientPubKey, ksToPs)
			if priviledges != nil {
				var token = createToken(priviledges, priv)
				io.WriteString(w, token)
			        handler.ServeHTTP(w, r)
			}else{
				return //TODO: write "you are not trusted" message back to client
			}
	        }else{
	                //fail because we have too many certs or 0 certs TODO: send back error
	                return
	        }
	})

}


func getPriviledges(pubKey string, ksToPs lightning.KeysToPriviledges) []string {
	for _, kToPs := range ksToPs.KsToPs {
		if kToPs.PubKey == pubKey {
			return kToPs.Priviledges
		}
	}
	return nil
}

func createToken(priviledges []string, priv []byte) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims {
		"priviledges": priviledges,
		"timestamp": strconv.FormatInt((time.Now().Unix()), 10),
	})
	tokenWithSig, _ := token.SignedString(priv)
	//TODO err checking
	return tokenWithSig
}
