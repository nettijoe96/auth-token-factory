package main

import (
	"net/http"
	"html/template"
	"io/ioutil"
	"crypto/x509"
	"encoding/pem"
	"encoding/hex"
	"os"
)



var trustkey string = "trustkey"
var graphqlAdmin string = "graphql-admin"


type Page struct {
	Title string
	Body []byte
}

func (p *Page) save () error {
	f := p.Title + ".txt"
	return ioutil.WriteFile(f, p.Body, 0600)
}

func load(title string) (*Page, error) {
	f := title + ".txt"
	body, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return &Page{Title: title, Body: body}, nil
}

func demo(w http.ResponseWriter, r *http.Request) {
	var certfile string = FlagMap["certfile"].(string)
	var keyfile string = FlagMap["keyfile"].(string)
	var name string = "serviceName"
	var bPub []byte = getPubFromCert(certfile, keyfile)
	var strPub string = hex.EncodeToString(bPub)
	var cmd string  = trustkey + " " + name + " " + graphqlAdmin + " " + strPub
	p := &Page{Title: "demo", Body: []byte(cmd)}
	p.save()
	t, _ := template.ParseFiles("demo.html")
	t.Execute(w, p)
}

func token(w http.ResponseWriter, r *http.Request) {
	var rawToken []byte = TestAuth()
	p := &Page{Title: "token", Body: rawToken}
	p.save()
	t, _ := template.ParseFiles("token.html")
	t.Execute(w, p)
}


func getPubFromCert(certfile, keyfile string) []byte {
	f, _ := os.Open(certfile)
	data, _ := ioutil.ReadAll(f)
	block, _ := pem.Decode(data)
	x509cert, _ := x509.ParseCertificate(block.Bytes)
	bPub, _ := x509.MarshalPKIXPublicKey(x509cert.PublicKey)
	return bPub
}


func main() {
	Flags()
	http.HandleFunc("/demo/", demo)
	http.HandleFunc("/token/", token)
	http.ListenAndServe(":9740", nil)
}



