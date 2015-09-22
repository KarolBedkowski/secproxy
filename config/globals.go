package config

import (
	log "k.prv/secproxy/logging"
	"sync"
)

type (
	Globals struct {
		Debug        bool
		Config       *AppConfiguration
		Endpoints    *EndpointsConf
		Users        *UsersConf
		confFilename string

		mu sync.RWMutex
	}
)

func NewGlobals(confFilename string, debug int) *Globals {
	globals := &Globals{}
	globals.confFilename = confFilename
	globals.Debug = debug > 0
	globals.ReloadConfig()

	if globals.Config.EndpointsFilename == "" {
		log.Error("Missing endpoints configuration file")
		panic("missing endpoints")
	}

	globals.Endpoints, _ = LoadEndpoints(globals.Config.EndpointsFilename)
	globals.Users, _ = LoadUsers(globals.Config.UsersFilename)

	globals.Users.SaveUsers("1.toml")
	return globals
}

func (g *Globals) ReloadConfig() {
	log.Info("Globals.ReloadConfig from ", g.confFilename)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Config, _ = LoadConfiguration(g.confFilename)
	log.Info("Globals.ReloadConfig from ", g.confFilename, " DONE")
}

func (g *Globals) GetUser(login string) (u *User) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, usr := range g.Users.Users {
		if usr.Login == login {
			return &usr
		}
	}
	return nil
}

func (g *Globals) SaveUser(u *User) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for idx, usr := range g.Users.Users {
		if usr.Login == u.Login {
			g.Users.Users[idx] = *u
			g.Users.SaveUsers(g.Config.UsersFilename)
			return
		}
	}
	g.Users.Users = append(g.Users.Users, *u)
	g.Users.SaveUsers(g.Config.UsersFilename)
}

func (g *Globals) GetEndpoint(name string) (e *EndpointConf) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, ep := range g.Endpoints.Endpoints {
		if ep.Name == name {
			return &ep
		}
	}
	return nil
}

func (g *Globals) SaveEndpoint(e *EndpointConf) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for idx, ep := range g.Endpoints.Endpoints {
		if ep.Name == e.Name {
			g.Endpoints.Endpoints[idx] = *e
			g.Endpoints.Save(g.Config.EndpointsFilename)
			return
		}
	}
	g.Endpoints.Endpoints = append(g.Endpoints.Endpoints, *e)
	g.Endpoints.Save(g.Config.EndpointsFilename)
}

func (g *Globals) DeleteEndpoint(name string) (ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for idx, ep := range g.Endpoints.Endpoints {
		if ep.Name == name {
			g.Endpoints.Endpoints = append(g.Endpoints.Endpoints[:idx],
				g.Endpoints.Endpoints[idx+1:]...)
			g.Endpoints.Save(g.Config.EndpointsFilename)
			return true
		}
	}
	return false
}
