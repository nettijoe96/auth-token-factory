package global

import (
	"github.com/niftynei/glightning/glightning"
)

type KeysToPrivileges struct {
        //defining the json encoding 
	KsToPs []KeyToPrivileges
}

type KeyToPrivileges struct {
	Service string
	Privileges []string
	PubKey string
}

var lightning *glightning.Lightning = glightning.NewLightning()
var plugin *glightning.Plugin


func GetGlobalLightning() *glightning.Lightning {
	return lightning
}

func GetGlobalPlugin() *glightning.Plugin {
	return plugin
}

func SetGlobalPlugin(p *glightning.Plugin) {
	plugin = p
}


