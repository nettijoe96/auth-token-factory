package main


import (
	"github.com/nettijoe96/jwt-factory/global"
	"github.com/nettijoe96/jwt-factory/plugin"
	"os"
)


func main() {
	plugin.Init(global.LightningDir)
	p := global.GetGlobalPlugin()
	p.Start(os.Stdin, os.Stdout)
}

