package config

import (
	"bytes"
	"encoding/gob"
	"github.com/cznic/kv"
	"io"
	"k.prv/secproxy/common"
	"os"
	"path/filepath"
	"sync"
)

type (
	Globals struct {
		Debug        bool
		Config       *AppConfiguration
		confFilename string

		db *kv.DB

		mu sync.RWMutex
	}
)

var (
	userPrefix     = []byte("U_")
	endpointPrefix = []byte("E_")
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
	if g.db != nil {
		g.db.Close()
		g.db = nil
	}
	log.Info("globals.Close DONE")
	return nil
}

func (g *Globals) ReloadConfig() {
	log.Info("Globals.ReloadConfig", "filename", g.confFilename)
	g.Close()

	g.mu.Lock()
	defer g.mu.Unlock()

	g.Config, _ = LoadConfiguration(g.confFilename)

	if g.Config.DBFilename == "" {
		log.Error("Missing endpoints configuration file; using ./database.db")
		g.Config.DBFilename = "./database.db"
	}

	g.openDatabases()
	log.Info("Globals.ReloadConfig DONE", "filename", g.confFilename)
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
	if common.FileExists(g.Config.DBFilename) {
		g.db, err = kv.Open(g.Config.DBFilename, dbOpts)
	} else {
		g.db, err = kv.Create(g.Config.DBFilename, dbOpts)
	}
	if err != nil {
		log.Error("config.g open db error", "err", err)
		panic("config.g open  db error " + err.Error())
	}
	if g.GetUser("admin") == nil {
		log.Info("config.g openDatabases creating 'admin' user with password 'admin'")
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
	log.Debug("globals.openDatabases DONE")
}

func (g *Globals) GetUser(login string) (u *User) {
	v, err := g.db.Get(nil, login2key(login))
	if err != nil {
		log.Warn("globals.GetUser error", "err", err)
	}
	if v == nil {
		log.Debug("globals.GetUser user not found", "login", login, "err", "not found")
		return nil
	}
	return decodeUser(v)
}

func login2key(login string) []byte {
	return append(userPrefix, []byte(login)...)
}

func decodeUser(buff []byte) (u *User) {
	u = &User{}
	r := bytes.NewBuffer(buff)
	dec := gob.NewDecoder(r)
	if err := dec.Decode(u); err == nil {
		return u
	} else {
		log.Warn("globals.decodeUser decode error", "err", err)
	}
	return nil
}

func (g *Globals) SaveUser(u *User) {
	log.Info("globals.SaveUser", u)
	r := new(bytes.Buffer)
	enc := gob.NewEncoder(r)
	if err := enc.Encode(u); err != nil {
		log.Warn("globals.SaveUser encode error", "err", err, "user", u)
		return
	}
	if err := g.db.Set(login2key(u.Login), r.Bytes()); err != nil {
		log.Warn("globals.SaveUser set error", "err", err, "user", u)
	}
}

func (g *Globals) GetUsers() (users []*User) {
	en, _, err := g.db.Seek(userPrefix)
	if err != nil {
		return
	}
	for {
		key, value, err := en.Next()
		if err == io.EOF || !bytes.HasPrefix(key, userPrefix) {
			break
		}
		if err == nil {
			users = append(users, decodeUser(value))
		} else {
			log.Error("GetUsers next error", "err", err)
		}
	}
	return
}

func endpoint2key(name string) []byte {
	return append(endpointPrefix, []byte(name)...)
}

func decodeEndpoint(buff []byte) (ec *EndpointConf) {
	ec = &EndpointConf{}
	r := bytes.NewBuffer(buff)
	dec := gob.NewDecoder(r)
	if err := dec.Decode(ec); err == nil {
		return ec
	} else {
		log.Warn("globals.decodeEndpoint decode error", "err", err)
	}
	return nil
}

func (g *Globals) GetEndpoint(name string) (e *EndpointConf) {
	v, err := g.db.Get(nil, endpoint2key(name))
	if err != nil {
		log.Warn("globals.GetEndpoint error", "err", err)
	}
	if v == nil {
		log.Debug("globals.GeEndpoint endpoint not found", "endpoint", name, "err", "not found")
		return nil
	}
	return decodeEndpoint(v)
}

func (g *Globals) SaveEndpoint(e *EndpointConf) {
	log.Info("globals.SaveEndpoint", e)
	r := new(bytes.Buffer)
	enc := gob.NewEncoder(r)
	if err := enc.Encode(e); err != nil {
		log.Warn("globals.SaveEndpoint encode error", "err", err, "endpointcfg", e)
		return
	}
	if err := g.db.Set(endpoint2key(e.Name), r.Bytes()); err != nil {
		log.Warn("globals.SaveEndpoint set error", "err", err, "endpointcfg", e)
	}
}

func (g *Globals) DeleteEndpoint(name string) (ok bool) {
	g.db.Delete(endpoint2key(name))
	return true
}

func (g *Globals) GetEndpoints() (eps []*EndpointConf) {
	en, _, err := g.db.Seek(endpointPrefix)
	if err != nil {
		return
	}
	for {
		key, value, err := en.Next()
		if err == io.EOF || !bytes.HasPrefix(key, endpointPrefix) {
			break
		}
		if err == nil {
			eps = append(eps, decodeEndpoint(value))
		} else {
			log.Error("GetUsers next error", "err", err)
		}
	}
	return
}

func (g *Globals) FindCerts() (names []string) {
	filepath.Walk(g.Config.CertsDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Error("globals.FindCerts error", "err", err, "path", g.Config.CertsDir)
				return err
			}
			if !info.IsDir() {
				names = append(names, path)
			}
			return nil
		})
	return
}
