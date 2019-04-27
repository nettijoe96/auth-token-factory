package main


import (
	"flag"
	"github.com/nettijoe96/auth-token-factory/lightning"
	"github.com/nettijoe96/auth-token-factory/plugin"
	"os"
)


func main() {
	var flagMap map[string]interface{} = standaloneFlags()
	//if plugin=false, then we do not create a plugin! (plugin=true by default)
	if flagMap["plugin"].(bool) {
	    plugin.Init(LightningDir)
	    p := lightning.GetGlobalPlugin()
	    p.Start(os.Stdin, os.Stdout)
	/*
	}else{
	    var isTLS bool = flagMap["tls"].(bool)
	    var certfile string = flagMap["certfile"].(string)
	    var keyfile string = flagMap["keyfile"].(string)
	    var api *plugin.StartApi
	    api.Standalone(isTLS, "9041", "graphql", certfile, keyfile, LightningDir)
	*/
        }
}


func standaloneFlags() map[string]interface{} {
	/* standalone app flags set here. See plugin/plugin.go for plugin options" */
	var isPlugin *bool = flag.Bool("plugin", true, "is running as a plugin")
	var certfile *string = flag.String("certfile", LightningDir + "cert.pem", "is running tls")
	var keyfile *string = flag.String("keyfile", LightningDir + "key.pem", "is running tls")
	flagMap := make(map[string]interface{})
	flag.Parse()
	flagMap["plugin"] = *isPlugin
	flagMap["certfile"] = *certfile
	flagMap["keyfile"] = *keyfile

	return flagMap
}

