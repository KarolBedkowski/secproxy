package config

import (
	"github.com/naoina/toml"
	"io/ioutil"
	log "k.prv/secproxy/logging"
)

var AppVersion = "dev"

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
		EndpointsFilename string
		UsersFilename     string

		AdminPanel AdminPanelConf
	}
)

// LoadConfiguration from given file
func LoadConfiguration(filename string) (conf *AppConfiguration, err error) {
	log.Info("config.LoadConfiguration: ", filename)
	var content []byte
	conf = &AppConfiguration{}
	conf.loadDefaults()
	content, err = ioutil.ReadFile(filename)
	if err == nil {
		if err = toml.Unmarshal(content, conf); err != nil {
			panic(err)
		}
	} else {
		log.Error("config.LoadConfiguration: ", filename, err.Error())
	}
	conf.validate()
	return
}

// SaveConfiguration write current configuration to json file
func (ac *AppConfiguration) SaveConfiguration(filename string) error {
	log.Info("config.SaveConfiguration: ", filename)
	data, err := toml.Marshal(ac)
	if err != nil {
		log.Error("config.SaveConfiguration Marshal ", filename, err.Error())
		return err
	}
	err = ioutil.WriteFile(filename, data, 0600)
	if err != nil {
		log.Error("config.SaveConfiguration: ", filename, err.Error())
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
}

func (ac *AppConfiguration) validate() bool {
	return true
}
