package factory

import (
	"crypto/x509"
	"encoding/hex"
	"net/http"
)

func CreateJWTHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	        var peerCerts []*x509.Certificate = r.TLS.PeerCertificates
	        var bClientPubKey []byte
		var xClientPubKey string
	        if len(peerCerts) == 1 {
		        //grab pub key
		        bClientPubKey = peerCerts[0].PublicKey.([]byte)
			xClientPubKey = hex.Dump(bClientPubKey)
			var isTrusted bool = checkForPubKeyInTrustedKeys(xClientPubKey)
			if isTrusted {
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

func checkForPubKeyInTrustedKeys(pubkey string) bool{
	//get global plugin
	//read pub keys from file
	//check if one matches. If not, pubkey has not special priviledges.
	return true
}

func CreateTokenEndpoint(w http.ResponseWriter, r *http.Request) {
	//the header should contain the signature of the timestamp
	//the server checks signature using providied public key
	//server creates token based on status of public key
	//server returns token
	return
}
