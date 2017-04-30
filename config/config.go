package config

import (
	"github.com/naoina/toml"
	"io/ioutil"
	"k.prv/secproxy/common"
	"k.prv/secproxy/logging"
	"os"
)

var (
	AppVersion = "dev"
	log        = logging.NewLogger("config")
)

type (
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

		AdminPanel AdminPanelConf
	}
)

// LoadConfiguration from given file
func LoadConfiguration(filename string) (conf *AppConfiguration, err error) {
	llog := log.With("filename", filename)
	llog.Info("config.LoadConfiguration")
	var content []byte
	conf = &AppConfiguration{}
	conf.loadDefaults()
	content, err = ioutil.ReadFile(filename)
	if err == nil {
		if err = toml.Unmarshal(content, conf); err != nil {
			panic(err)
		}
	} else {
		llog.With("err", err).Error("config.LoadConfiguration error")
	}
	conf.validate()

	if !common.DirExists(conf.CertsDir) {
		llog.Info("config.LoadConfiguration dir for certs not exists - creating %s", conf.CertsDir)
		if err := os.MkdirAll(conf.CertsDir, 600); err != nil {
			llog.With("err", err).Panic("config.LoadConfiguration creating dir %s for certs failed", conf.CertsDir)
		}
	}

	return
}

// SaveConfiguration write current configuration to json file
func (ac *AppConfiguration) SaveConfiguration(filename string) error {
	llog := log.With("filename", filename)
	llog.Info("config.SaveConfiguration")
	data, err := toml.Marshal(*ac)
	if err != nil {
		log.With("err", err).Error("config.SaveConfiguration Marshal error; conf=%+v", ac)
		return err
	}
	err = ioutil.WriteFile(filename, data, 0700)
	if err != nil {
		log.With("err", err).Error("config.SaveConfiguration error")
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
}

func (ac *AppConfiguration) validate() bool {
	return true
}

func (ac *AppConfiguration) String() string {
	data, err := toml.Marshal(*ac)
	if err != nil {
		log.With("err", err).Error("config.String Marshal error; conf=%+v", ac)
		return err.Error()
	}
	return string(data)
}
