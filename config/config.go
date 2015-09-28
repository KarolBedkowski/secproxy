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
	log.Info("config.LoadConfiguration", "filename", filename)
	var content []byte
	conf = &AppConfiguration{}
	conf.loadDefaults()
	content, err = ioutil.ReadFile(filename)
	if err == nil {
		if err = toml.Unmarshal(content, conf); err != nil {
			panic(err)
		}
	} else {
		log.Error("config.LoadConfiguration", "filename", filename, "err", err)
	}
	conf.validate()

	if !common.DirExists(conf.CertsDir) {
		log.Info("config.LoadConfiguration dir for certs not exists - creating", "path", conf.CertsDir)
		if err := os.MkdirAll(conf.CertsDir, 600); err != nil {
			log.Crit("config.LoadConfiguration creating dir for certs failed",
				"path", conf.CertsDir, "err", err)
		}
	}

	return
}

// SaveConfiguration write current configuration to json file
func (ac *AppConfiguration) SaveConfiguration(filename string) error {
	log.Info("config.SaveConfiguration", "filename", filename)
	data, err := toml.Marshal(ac)
	if err != nil {
		log.Error("config.SaveConfiguration Marshal", "filename", filename, "err", err, "conf", ac)
		return err
	}
	err = ioutil.WriteFile(filename, data, 0700)
	if err != nil {
		log.Error("config.SaveConfiguration", "filename", filename, "err", err)
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
