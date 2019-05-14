package main_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"
)

var flagMap map[string]interface{}

func TestMain(m *testing.M) {
        flagMap = flags()
	os.Exit(m.Run())
}


func flags() map[string]interface{} {
	var certfile *string  = flag.String("certfile", "", "full path to client x509 self-signed cert")
	var keyfile *string  = flag.String("keyfile", "", "full path to client rsa key")
	var serveraddr *string  = flag.String("serveraddr", "127.0.0.1:9741", "addr:port to server (for cert SANs name matching and connecting to the server)")
	fm := make(map[string]interface{})
	flag.Parse()
	fm["certfile"] = *certfile
	fm["keyfile"] = *keyfile
	fm["serveraddr"] = *serveraddr

	return fm
}

/*
clightning must be running with auth-token-factory plugin!
*/
func TestAuth(t *testing.T) {
	var certfile string = flagMap["certfile"].(string)
	var keyfile string = flagMap["keyfile"].(string)
	var serveraddr string = flagMap["serveraddr"].(string)
	if certfile == "" || keyfile == "" || serveraddr == "" {
		log.Fatal("need --certfile path and --keyfile path in order to run tests")
	}
	var bPub []byte
	var err error
	cert, _ := tls.LoadX509KeyPair(certfile, keyfile)
	f, _ := os.Open(certfile)
	data, _ := ioutil.ReadAll(f)
	block, _ := pem.Decode(data)
	x509cert, err := x509.ParseCertificate(block.Bytes)
	bPub, err = x509.MarshalPKIXPublicKey(x509cert.PublicKey)
	fmt.Println("Add this raw hex of pubkey as trust key if you have not already done so!:\n", hex.EncodeToString(bPub))
	fmt.Println("Command to add pubkey to trusted keys: ./lightning-cli trustkey <raw key> a,b,c")
	client := &http.Client {
		Transport: &http.Transport {
			TLSClientConfig: &tls.Config {
				ClientAuth: tls.RequireAnyClientCert,
				Certificates: []tls.Certificate{cert},
				ServerName: serveraddr,
				InsecureSkipVerify: true,
			},
		},
	}
	r, err := client.Get("https://" + serveraddr)
	if err != nil {
                log.Fatal(err)
        }
	body, _ := ioutil.ReadAll(r.Body)
	fmt.Println("token result:\n", string(body))
}





