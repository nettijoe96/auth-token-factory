package main


import (
	"github.com/nettijoe96/auth-token-factory/lightning"
	"github.com/nettijoe96/auth-token-factory/plugin"
	"os"
)


func main() {
	plugin.Init(LightningDir)
	p := lightning.GetGlobalPlugin()
	p.Start(os.Stdin, os.Stdout)
}

