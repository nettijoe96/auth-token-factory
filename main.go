package main


import (
	"github.com/nettijoe96/jwt-factory/lightning"
	"github.com/nettijoe96/jwt-factory/plugin"
	"os"
)


func main() {
	plugin.Init(LightningDir)
	p := lightning.GetGlobalPlugin()
	p.Start(os.Stdin, os.Stdout)
}

