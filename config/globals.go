package config

import (
	"bytes"
	"encoding/gob"
	"github.com/cznic/kv"
	"io"
	"k.prv/secproxy/common"
	log "k.prv/secproxy/logging"
	"sync"
)

type (
	Globals struct {
		Debug        bool
		Config       *AppConfiguration
		confFilename string

		dbEndpoints *kv.DB
		dbUsers     *kv.DB

		mu sync.RWMutex
	}
)

func NewGlobals(confFilename string, debug int) *Globals {
	globals := &Globals{}
	globals.confFilename = confFilename
	globals.Debug = debug > 0
	globals.ReloadConfig()
	return globals
}

func (g *Globals) Close() error {
	log.Info("globals.Close")
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.dbUsers != nil {
		g.dbUsers.Close()
		g.dbUsers = nil
	}
	if g.dbEndpoints != nil {
		g.dbEndpoints.Close()
		g.dbEndpoints = nil
	}
	log.Info("globals.Close DONE")
	return nil
}

func (g *Globals) ReloadConfig() {
	log.Info("Globals.ReloadConfig from ", g.confFilename)
	g.Close()

	g.mu.Lock()
	defer g.mu.Unlock()

	g.Config, _ = LoadConfiguration(g.confFilename)

	if g.Config.EndpointsFilename == "" {
		log.Error("Missing endpoints configuration file; using ./endpoints.db")
		g.Config.EndpointsFilename = "./endpoints.db"
	}

	if g.Config.UsersFilename == "" {
		log.Error("Missing UsersFilename configuration file; using ./users.db")
		g.Config.UsersFilename = "./users.db"
	}

	g.openDatabases()
	log.Info("Globals.ReloadConfig from ", g.confFilename, " DONE")
}

func (g *Globals) openDatabases() {
	log.Debug("globals.openDatabases START")
	dbOpts := &kv.Options{
		VerifyDbBeforeOpen:  true,
		VerifyDbAfterOpen:   true,
		VerifyDbBeforeClose: true,
		VerifyDbAfterClose:  true,
	}

	var err error
	if common.FileExists(g.Config.EndpointsFilename) {
		g.dbEndpoints, err = kv.Open(g.Config.EndpointsFilename, dbOpts)
	} else {
		g.dbEndpoints, err = kv.Create(g.Config.EndpointsFilename, dbOpts)
	}
	if err != nil {
		log.Error("config.g open enpoints db error ", err)
		panic("config.g open enpoints db error " + err.Error())
	}
	if common.FileExists(g.Config.UsersFilename) {
		g.dbUsers, err = kv.Open(g.Config.UsersFilename, dbOpts)
	} else {
		g.dbUsers, err = kv.Create(g.Config.UsersFilename, dbOpts)
	}
	if err != nil {
		log.Error("config.g open users db error ", err)
		panic("config.g open users db error " + err.Error())
	} else {
		if g.GetUser("admin") == nil {
			admin := &User{
				Login: "admin",
				Name:  "Administrator",
				Role:  "ADMIN",
			}
			admin.UpdatePassword("admin")
			g.SaveUser(admin)
		}
		if g.GetUser("admin") == nil {
			panic("missing admin")
		}
	}
	log.Debug("globals.openDatabases DONE")
}

func (g *Globals) GetUser(login string) (u *User) {
	v, err := g.dbUsers.Get(nil, []byte(login))
	if err != nil {
		log.Warn("globals.GetUser error ", err)
	}
	if v == nil {
		log.Debug("globals.GetUser user not found ", login)
		return nil
	}
	return decodeUser(v)
}

func decodeUser(buff []byte) (u *User) {
	u = &User{}
	r := bytes.NewBuffer(buff)
	dec := gob.NewDecoder(r)
	if err := dec.Decode(u); err == nil {
		return u
	} else {
		log.Warn("globals.decodeUser decode error ", err)
	}
	return nil
}

func (g *Globals) SaveUser(u *User) {
	log.Info("globals.SaveUser ", u)
	r := new(bytes.Buffer)
	enc := gob.NewEncoder(r)
	if err := enc.Encode(u); err != nil {
		log.Warn("globals.SaveUser encode error ", err)
		return
	}
	if err := g.dbUsers.Set([]byte(u.Login), r.Bytes()); err != nil {
		log.Warn("globals.SaveUser set error ", err)
	}
}

func (g *Globals) GetUsers() (users []*User) {
	en, err := g.dbUsers.SeekFirst()
	if err != nil {
		return
	}
	for {
		_, value, err := en.Next()
		if err == nil {
			users = append(users, decodeUser(value))
		} else if err == io.EOF {
			break
		} else {
			log.Error("GetUsers next error ", err)
		}
	}
	return
}

func decodeEndpoint(buff []byte) (ec *EndpointConf) {
	ec = &EndpointConf{}
	r := bytes.NewBuffer(buff)
	dec := gob.NewDecoder(r)
	if err := dec.Decode(ec); err == nil {
		return ec
	} else {
		log.Warn("globals.decodeEndpoint decode error ", err)
	}
	return nil
}

func (g *Globals) GetEndpoint(name string) (e *EndpointConf) {
	v, err := g.dbEndpoints.Get(nil, []byte(name))
	if err != nil {
		log.Warn("globals.GetEndpoint error ", err)
	}
	if v == nil {
		log.Debug("globals.GeEndpoint endpoint not found ", name)
		return nil
	}
	return decodeEndpoint(v)
}

func (g *Globals) SaveEndpoint(e *EndpointConf) {
	log.Info("globals.SaveEndpoint ", e)
	r := new(bytes.Buffer)
	enc := gob.NewEncoder(r)
	if err := enc.Encode(e); err != nil {
		log.Warn("globals.SaveEndpoint encode error ", err)
		return
	}
	if err := g.dbEndpoints.Set([]byte(e.Name), r.Bytes()); err != nil {
		log.Warn("globals.SaveEndpoint set error ", err)
	}
}

func (g *Globals) DeleteEndpoint(name string) (ok bool) {
	g.dbEndpoints.Delete([]byte(name))
	return true
}

func (g *Globals) GetEndpoints() (eps []*EndpointConf) {
	en, err := g.dbEndpoints.SeekFirst()
	if err != nil {
		return
	}
	for {
		_, value, err := en.Next()
		if err == nil {
			eps = append(eps, decodeEndpoint(value))
		} else if err == io.EOF {
			break
		} else {
			log.Error("GetUsers next error ", err)
		}
	}
	return
}
