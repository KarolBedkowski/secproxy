package config

import (
	log "k.prv/secproxy/logging"
	"sync"
)

type (

	Globals struct {
		Config          *AppConfiguration
		Endpoints       *EndpointsConf
		confFilename    string

		mu sync.RWMutex
	}
)

func NewGlobals(confFilename string, debug int) *Globals {
	globals := &Globals{}
	globals.confFilename = confFilename
	globals.ReloadConfig()

	if globals.Config.EndpointsFilename == "" {
		log.Error("Missing endpoints configuration file")
		panic("missing endpoints")
	}

	globals.Endpoints, _ = LoadEndpoints(globals.Config.EndpointsFilename)

	return globals
}

func (g *Globals) ReloadConfig() {
	log.Info("Globals.ReloadConfig from ", g.confFilename)
	g.Config, _ = LoadConfiguration(g.confFilename)
	log.Info("Globals.ReloadConfig from ", g.confFilename, " DONE")
}
