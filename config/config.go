package config

import (
	"github.com/naoina/toml"
	"io/ioutil"
	"k.prv/secproxy/common"
	"k.prv/secproxy/logging"
	"os"
)

var (
	// AppVersion contains date and version built application
	AppVersion = "0.1+dev"
	logConfig  = logging.NewLogger("config.config")
)

type (
	// AdminPanelConf is configuration administration panel
	AdminPanelConf struct {
		HTTPAddress     string
		HTTPSAddress    string
		SslCert         string
		SslKey          string
		CookieAuthKey   string
		CookieEncKey    string
		SessionStoreDir string
		StaticDir       string
		TemplatesDir    string
	}

	// AppConfiguration Main app configuration.
	AppConfiguration struct {
		DBFilename string
		CertsDir   string
		CARootsDir string

		AdminPanel AdminPanelConf

		Ldap LDAPConfiguration
	}
)

// LoadConfiguration from given file
func LoadConfiguration(filename string) (conf *AppConfiguration) {
	llog := logConfig.With("filename", filename)
	llog.Info("Config: loading...")
	conf = &AppConfiguration{}
	conf.loadDefaults()
	if content, err := ioutil.ReadFile(filename); err == nil {
		if err = toml.Unmarshal(content, conf); err != nil {
			llog.With("err", err).Panic("Config: parse error")
		}
	} else {
		llog.With("err", err).Panic("Config: file load error")
	}
	if err := conf.validate(); err != nil {
		llog.With("err", err).Panic("Config: validation error")
		return
	}

	if !common.DirExists(conf.CertsDir) {
		llog.Info("Config: dir for certs not exists - creating %s", conf.CertsDir)
		if err := os.MkdirAll(conf.CertsDir, 0700); err != nil {
			llog.With("err", err).Panic("Config: creating dir %s for certs failed", conf.CertsDir)
		}
	}

	if !common.DirExists(conf.CARootsDir) {
		llog.Info("Config: dir for CA certs not exists - creating %s", conf.CARootsDir)
		if err := os.MkdirAll(conf.CARootsDir, 0700); err != nil {
			llog.With("err", err).Panic("Config: creating dir %s for CA certs failed", conf.CARootsDir)
		}
	}

	return
}

// SaveConfiguration write current configuration to json file
func (ac *AppConfiguration) SaveConfiguration(filename string) error {
	llog := logConfig.With("filename", filename)
	llog.Info("Config: saving...")
	data, err := toml.Marshal(*ac)
	if err != nil {
		llog.With("err", err).Error("Config: save marshal error; conf=%+v", ac)
		return err
	}
	err = ioutil.WriteFile(filename, data, 0700)
	if err != nil {
		llog.With("err", err).Error("Config: save error")
	}
	return err
}

func (ac *AppConfiguration) loadDefaults() {
	ac.AdminPanel.CookieAuthKey = "12345678901234567890123456789012"
	ac.AdminPanel.CookieEncKey = "12345678901234567890123456789012"
	ac.AdminPanel.SessionStoreDir = "./temp"
	ac.AdminPanel.StaticDir = "./static"
	ac.AdminPanel.TemplatesDir = "./templates"
	ac.AdminPanel.HTTPAddress = ":8000"
	ac.AdminPanel.HTTPSAddress = ""
	ac.AdminPanel.SslCert = "key.pem"
	ac.AdminPanel.SslKey = "cert.pem"
	ac.CertsDir = "./certs"
	ac.CARootsDir = "./certs-ca"
	ac.Ldap.Enable = false
}

func (ac *AppConfiguration) validate() error {
	if err := ac.Ldap.Validate(); err != nil {
		return err
	}
	return nil
}

func (ac *AppConfiguration) String() string {
	data, err := toml.Marshal(*ac)
	if err != nil {
		logConfig.With("err", err).Error("Config: marshal error")
		return err.Error()
	}
	return string(data)
}
