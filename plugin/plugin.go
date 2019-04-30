package plugin


import (
	"fmt"
	"crypto/tls"
	"encoding/json"
	"github.com/nettijoe96/auth-token-factory/factory"
	"github.com/nettijoe96/auth-token-factory/lightning"
	"github.com/niftynei/glightning/glightning"
	"github.com/niftynei/glightning/jrpc2"
	"github.com/pkg/errors"
	"net/http"
	"os"
	"strings"
)



func Init(lightningDir string) {
	plugin := lightning.GetGlobalPlugin()
	plugin = glightning.NewPlugin(InitFunc)
	plugin.RegisterOption(glightning.NewOption("factory-port", "port api is available on. default: 9741", "9741"))
	plugin.RegisterOption(glightning.NewOption("factory-page", "page api is available on. default: factory", "factory"))
	plugin.RegisterOption(glightning.NewOption("certfile", "server certificate. User must approve this certificate. Default cert locaiton is lightningDir/cert.pem", lightningDir + "cert.pem"))
	plugin.RegisterOption(glightning.NewOption("keyfile", "private key file of the public key in the server certificate. Default key location is lightningDir/key.pem.", lightningDir + "key.pem"))
	plugin.RegisterOption(glightning.NewOption("factory-trustedkeyfile", "private key file of the public key in the server certificate. Default location is in lightningDir/trustedkeys.json.", lightningDir + "trustedkeys.json"))
	trustKeyMethod := glightning.NewRpcMethod(&trustKey{}, "run lightning graphql api")
	trustKeyMethod.LongDesc = "add a trusted pubkey"
	plugin.RegisterMethod(trustKeyMethod)
	lightning.SetGlobalPlugin(plugin)
}

func InitFunc(p *glightning.Plugin, o map[string]string, config *glightning.Config) {
	//var page string = o["factory-page"]
	var port string = o["factory-port"]
	var certfile string = o["certfile"]
	var keyfile string = o["keyfile"]
	l := lightning.GetGlobalLightning()
	l.StartUp(config.RpcFile, config.LightningDir)
	//h := http.NewServeMux()
	var server *http.Server = &http.Server {
		Addr: ":" + port,
		//Handler: factory.CreateJWTHandler(h),
		Handler: factory.JWTHandler{},
		TLSConfig: &tls.Config {
			ClientAuth: tls.RequireAnyClientCert,
			ServerName: "127.0.0.1",
		},
	}
	go server.ListenAndServeTLS(certfile, keyfile)
}

type trustKey struct {
	//defining the args of the trustKey method`
	PubKey string
	Priviledges string
}

func (t *trustKey) New() interface{} {
	return &trustKey{}
}

func (t *trustKey) Name() string {
	return "trustkey"
}

func (t *trustKey) Call() (jrpc2.Result, error) {
	plugin := lightning.GetGlobalPlugin()
	var ksToPsFile string = plugin.GetOptionValue("factory-trustedkeyfile")
	f, err := os.Open(ksToPsFile)
	if err != nil {
		err = errors.Wrap(err, "failed to open ksToPsFile in trustKey.Call()")
		return nil, err
	}
	var decoder *json.Decoder = json.NewDecoder(f)
	var encoder *json.Encoder
	var ksToPs lightning.KeysToPriviledges
	var pubkey string = t.PubKey
	var priviledges []string = strings.Split(t.Priviledges, ",")
	decoder.Decode(&ksToPs)
	f.Close()
	ksToPs.KsToPs = append(ksToPs.KsToPs, lightning.KeyToPriviledges{pubkey, priviledges})
	f, err = os.Create(ksToPsFile)
	if err != nil {
		err = errors.Wrap(err, "failed to create new ksToPsFile file in trustKey.Call()")
		return nil, err
	}
        encoder = json.NewEncoder(f)
	encoder.Encode(ksToPs)
	f.Close()
	return fmt.Sprintf("added trust for public key", t.PubKey, "for priviledges", t.Priviledges), err
}
