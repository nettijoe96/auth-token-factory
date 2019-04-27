package lightning

import (
	"github.com/niftynei/glightning/glightning"
)

type KeysToPriviledges struct {
        //defining the json encoding 
	KsToPs []KeyToPriviledges
}

type KeyToPriviledges struct {
	PubKey string
	Priviledges []string
}

var lightning *glightning.Lightning = glightning.NewLightning()
var plugin *glightning.Plugin


func GetGlobalLightning() *glightning.Lightning {
	return lightning
}

func GetGlobalPlugin() *glightning.Plugin {
	return plugin
}


