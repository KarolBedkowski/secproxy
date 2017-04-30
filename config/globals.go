package config

import (
	"bytes"
	"encoding/gob"
	"flag"
	"fmt"
	"github.com/boltdb/bolt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type (
	Globals struct {
		Config  *AppConfiguration
		DevMode bool

		confFilename string
		db           *bolt.DB
		mu           sync.RWMutex
	}
)

var (
	usersBucket     = []byte("users")
	endpointsBucket = []byte("endpoints")

	configFilenameFlag = flag.String("config", "./config.toml", "Configuration file name")
	devModeFlag        = flag.Bool("devMode", false, "Run in development mode")
)

func NewGlobals() *Globals {
	globals := &Globals{
		confFilename: *configFilenameFlag,
		DevMode:      *devModeFlag,
	}
	globals.ReloadConfig()
	if globals.DevMode {
		log.Warn("DEV MODE ENABLED")
	}
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
	bdb, err := bolt.Open(g.Config.DBFilename, 0600, &bolt.Options{Timeout: 10 * time.Second})
	if err != nil {
		panic("config.g open  db error " + err.Error())
	}

	err = bdb.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(usersBucket); err != nil {
			return fmt.Errorf("db create bucket error: %s", err.Error())
		}
		if _, err := tx.CreateBucketIfNotExists(endpointsBucket); err != nil {
			return fmt.Errorf("db create bucket error: %s", err.Error())
		}
		return nil
	})

	if err != nil {
		bdb.Close()
		panic("open create buckets error: " + err.Error())
	}

	g.db = bdb

	if u := g.GetUser("admin"); u == nil {
		log.Info("config.g openDatabases creating 'admin' user with password 'admin'")
		admin := &User{
			Login:  "admin",
			Name:   "Administrator",
			Role:   "ADMIN",
			Active: true,
		}
		admin.UpdatePassword("admin")
		g.SaveUser(admin)
	} else {
		if !u.Active {
			log.Warn("config.g openDatabases re-active Admin user")
			u.Active = true
			g.SaveUser(u)
		}
	}
	if g.GetUser("admin") == nil {
		panic("missing admin")
	}
	log.Debug("globals.openDatabases DONE")
}

func (g *Globals) GetUser(login string) (u *User) {
	var v []byte
	err := g.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		v = b.Get(login2key(login))
		return nil
	})
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
	return []byte(login)
}

func decodeUser(buff []byte) (u *User) {
	u = &User{}
	r := bytes.NewBuffer(buff)
	dec := gob.NewDecoder(r)
	if err := dec.Decode(u); err != nil {
		log.Warn("globals.decodeUser decode error", "err", err)
		return nil
	}
	return u
}

func (g *Globals) SaveUser(u *User) {
	log.Info("globals.SaveUser", "user", u)
	r := new(bytes.Buffer)
	enc := gob.NewEncoder(r)
	if err := enc.Encode(u); err != nil {
		log.Warn("globals.SaveUser encode error", "err", err, "user", u)
		return
	}
	err := g.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		return b.Put(login2key(u.Login), r.Bytes())
	})
	if err != nil {
		log.Warn("globals.SaveUser set error", "err", err, "user", u)
	}
}

func (g *Globals) GetUsers() (users []*User) {
	err := g.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		return b.ForEach(func(k, v []byte) error {
			users = append(users, decodeUser(v))
			return nil
		})
	})
	if err != nil {
		log.Error("GetUsers error", "err", err)
	}
	return
}

func endpoint2key(name string) []byte {
	return []byte(name)
}

func decodeEndpoint(buff []byte) (ec *EndpointConf) {
	ec = &EndpointConf{}
	r := bytes.NewBuffer(buff)
	dec := gob.NewDecoder(r)
	if err := dec.Decode(ec); err != nil {
		log.Warn("globals.decodeEndpoint decode error", "err", err)
		return nil
	}
	return ec
}

func (g *Globals) GetEndpoint(name string) (e *EndpointConf) {
	var v []byte
	err := g.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(endpointsBucket)
		v = b.Get(endpoint2key(name))
		return nil
	})
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
	err := g.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(endpointsBucket)
		return b.Put(endpoint2key(e.Name), r.Bytes())
	})
	if err != nil {
		log.Warn("globals.SaveEndpoint set error", "err", err, "endpointcfg", e)
	}
}

func (g *Globals) DeleteEndpoint(name string) (ok bool) {
	err := g.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(endpointsBucket)
		return b.Delete(endpoint2key(name))
	})
	return err == nil
}

func (g *Globals) GetEndpoints() (eps []*EndpointConf) {
	err := g.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(endpointsBucket)
		return b.ForEach(func(k, v []byte) error {
			eps = append(eps, decodeEndpoint(v))
			return nil
		})
	})
	if err != nil {
		log.Error("GetUsers next error", "err", err)
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

func (g *Globals) CertUsed(name string) (epname string, used bool) {
	for _, ep := range g.GetEndpoints() {
		if ep.SslCert == name || ep.SslKey == name {
			return ep.Name, true
		}
	}
	return "", false
}
