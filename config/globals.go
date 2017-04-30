package config

import (
	"bytes"
	"encoding/gob"
	"flag"
	"fmt"
	"github.com/boltdb/bolt"
	"k.prv/secproxy/logging"
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

	logGlobals = logging.NewLogger("config.globals")
)

func NewGlobals() *Globals {
	globals := &Globals{
		confFilename: *configFilenameFlag,
		DevMode:      *devModeFlag,
	}
	globals.ReloadConfig()
	if globals.DevMode {
		logGlobals.Warn("DEV MODE ENABLED")
	}
	return globals
}

func (g *Globals) Close() error {
	logGlobals.Info("Globals: Closeing")
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.db != nil {
		g.db.Close()
		g.db = nil
	}
	logGlobals.Info("globals.Close DONE")
	return nil
}

func (g *Globals) ReloadConfig() {
	llog := logGlobals.With("filename", g.confFilename)
	llog.Info("Globals: Reloading config")
	g.Close()

	g.mu.Lock()
	defer g.mu.Unlock()

	g.Config, _ = LoadConfiguration(g.confFilename)

	if g.Config.DBFilename == "" {
		llog.Warn("Globals: Missing endpoints configuration file; using ./database.db")
		g.Config.DBFilename = "./database.db"
	}

	g.openDatabases()
	llog.Info("Globals: configuration reloaded")
}

func (g *Globals) openDatabases() {
	logGlobals.Debug("Globals: opening database")
	bdb, err := bolt.Open(g.Config.DBFilename, 0600, &bolt.Options{Timeout: 10 * time.Second})
	if err != nil {
		logGlobals.With("err", err).Panic("Globals: open database failed")
		return
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
		logGlobals.With("err", err).Panic("Globals: create buckets error")
	}

	g.db = bdb

	if u := g.GetUser("admin"); u == nil {
		logGlobals.Info("Globals: creating 'admin' user with password 'admin'")
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
			logGlobals.Warn("Globals: re-active Admin user")
			u.Active = true
			g.SaveUser(u)
		}
	}
	if g.GetUser("admin") == nil {
		panic("missing admin")
	}
	logGlobals.Debug("Globals: database opened")
}

func (g *Globals) GetUser(login string) (u *User) {
	var v []byte
	err := g.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		v = b.Get(login2key(login))
		return nil
	})

	ilog := logGlobals.With("login", login)

	if err != nil {
		ilog.With("err", err).Warn("Globals: get user error")
	}
	if v == nil {
		ilog.With("err", "not found").Debug("Globals: user not found")
		return nil
	}

	u, err = decodeUser(v)
	if err != nil {
		ilog.With("err", err).Warn("Globals: decode user error")
	}

	return u
}

func login2key(login string) []byte {
	return []byte(login)
}

func decodeUser(buff []byte) (u *User, err error) {
	u = &User{}
	r := bytes.NewBuffer(buff)
	dec := gob.NewDecoder(r)
	if err := dec.Decode(u); err != nil {
		return nil, err
	}
	return u, nil
}

func (g *Globals) SaveUser(u *User) {
	llog := logGlobals.With("user", u.Login)
	llog.Debug("Globals: saving user...")
	r := new(bytes.Buffer)
	enc := gob.NewEncoder(r)
	if err := enc.Encode(u); err != nil {
		llog.With("err", err).Warn("Globals: save user - encode error; u=%+v", u)
		return
	}
	err := g.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		return b.Put(login2key(u.Login), r.Bytes())
	})
	if err != nil {
		llog.With("err", err).Warn("Globals: save error")
	} else {
		llog.Info("Globals: user saved")
	}
}

func (g *Globals) GetUsers() (users []*User) {
	err := g.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		return b.ForEach(func(k, v []byte) error {
			u, err := decodeUser(v)
			if err != nil {
				return fmt.Errorf("decode user error: %s", err)
			} else {
				users = append(users, u)
			}
			return nil
		})
	})
	if err != nil {
		logGlobals.With("err", err).Error("Globals: get users error")
	}
	return
}

func endpoint2key(name string) []byte {
	return []byte(name)
}

func decodeEndpoint(buff []byte) (ec *EndpointConf, err error) {
	ec = &EndpointConf{}
	r := bytes.NewBuffer(buff)
	dec := gob.NewDecoder(r)
	err = dec.Decode(ec)
	return ec, err
}

func (g *Globals) GetEndpoint(name string) (e *EndpointConf) {
	llog := logGlobals.With("endpoint", name)
	var v []byte
	err := g.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(endpointsBucket)
		v = b.Get(endpoint2key(name))
		return nil
	})
	if err != nil {
		llog.With("err", err).Warn("Globals: get endpoint error")
		return nil
	}
	if v == nil {
		llog.With("err", err).Debug("Globals: endpoint not found")
		return nil
	}
	e, err = decodeEndpoint(v)
	if err != nil {
		llog.With("err", err).Warn("Globals: decode loaded endpoint error")
	}
	return e
}

func (g *Globals) SaveEndpoint(e *EndpointConf) {
	llog := logGlobals.With("endpoint", e.Name)
	llog.Info("Globals: saving endpoint...")
	r := new(bytes.Buffer)
	enc := gob.NewEncoder(r)
	if err := enc.Encode(e); err != nil {
		llog.With("err", err).Warn("Globals: encode endpoint for save error; e=%+v", e)
		return
	}
	err := g.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(endpointsBucket)
		return b.Put(endpoint2key(e.Name), r.Bytes())
	})
	if err != nil {
		llog.With("err", err).Warn("Globals: save endpoint error")
	} else {
		llog.Info("Globals: endpoint saved")
	}
}

func (g *Globals) DeleteEndpoint(name string) (ok bool) {
	err := g.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(endpointsBucket)
		return b.Delete(endpoint2key(name))
	})
	if err != nil {
		logGlobals.With("err", err).With("endpoint", name).Warn("Globals: delete endpoint failed")
	}
	return err == nil
}

func (g *Globals) GetEndpoints() (eps []*EndpointConf) {
	err := g.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(endpointsBucket)
		return b.ForEach(func(k, v []byte) error {
			ep, err := decodeEndpoint(v)
			if err != nil {
				return fmt.Errorf("decode endpoint error %s", err)
			}
			eps = append(eps, ep)
			return nil
		})
	})
	if err != nil {
		logGlobals.With("err", err).Error("Globals: get endpoints error")
	}
	return
}

func (g *Globals) FindCerts() (names []string) {
	filepath.Walk(g.Config.CertsDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				logGlobals.With("err", err).
					With("path", g.Config.CertsDir).
					Error("Globals: find certs error")
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
