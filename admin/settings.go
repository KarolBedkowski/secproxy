package admin

import (
	"github.com/gorilla/mux"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"net/http"
)

var logSettings = logging.NewLogger("web")

func initSettingsHandlers(globals *config.Globals, parentRotuer *mux.Route) {
	router := parentRotuer.Subrouter()
	router.HandleFunc("/", securityContextHandler(settingsPageHandler, globals, "ADMIN"))
	router.HandleFunc("/setdebug", securityContextHandler(setdebugPageHandler, globals, "ADMIN"))
	router.HandleFunc("/confreload", securityContextHandler(confReloadPageHandler, globals, "ADMIN"))
}

func settingsPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		LogLevel      string
		Configuration string
	}{
		BasePageContext: bctx,
		LogLevel:        logging.GetLogLevel(),
		Configuration:   bctx.Globals.Config.String(),
	}

	renderTemplateStd(w, ctx, "settings.tmpl")
}

func setdebugPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	log := logSettings.WithRequest(r)
	r.ParseForm()
	level := ""
	if levels, ok := r.Form["l"]; ok && len(levels) > 0 {
		level = levels[0]
	}

	if logging.SetLogLevel(level) {
		log.Warn("NOTICE: Set logging level - change to level %v", level)
		bctx.AddFlashMessage("Logging level changed", "success")
		bctx.Save()
	} else {
		log.Info("Settings: bad log level: %v", level)
		http.Error(w, "Wrong arguments", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/settings/", http.StatusFound)
}

func confReloadPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	logSettings.WithRequest(r).Info("Settings: reload config request")
	bctx.Globals.ReloadConfig()
	bctx.AddFlashMessage("Configuration reloaded", "success")
	bctx.Save()
	http.Redirect(w, r, "/settings/", http.StatusFound)
}
