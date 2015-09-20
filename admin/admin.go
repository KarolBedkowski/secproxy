package admin

import (
	"k.prv/secproxy/config"
	log "k.prv/secproxy/logging"
	"net/http"
)

func StartAdmin(globals *config.Globals) {
	if globals.Config.AdminPanel.HTTPSAddress != "" {
		log.Info("admin.StartAdmin Listen HTTPS: ", globals.Config.AdminPanel.HTTPSAddress)
		if globals.Config.AdminPanel.HTTPAddress != "" {
			go func() {
				if err := http.ListenAndServeTLS(globals.Config.AdminPanel.HTTPSAddress,
					globals.Config.AdminPanel.SslCert, globals.Config.AdminPanel.SslKey, nil); err != nil {
					log.Error("admin.StartAdmin Error listening https, ", err)
				}
			}()
		} else {
			if err := http.ListenAndServeTLS(globals.Config.AdminPanel.HTTPSAddress,
				globals.Config.AdminPanel.SslCert, globals.Config.AdminPanel.SslKey, nil); err != nil {
				log.Error("admin.StartAdmin Error listening https, ", err)
			}
		}
	}

	if globals.Config.AdminPanel.HTTPAddress != "" {
		log.Info("admin.StartAdmin Listen: ", globals.Config.AdminPanel.HTTPAddress)
		if err := http.ListenAndServe(globals.Config.AdminPanel.HTTPAddress, nil); err != nil {
			log.Error("admin.StartAdmin Error listening http, ", err)
		}
	}
}
