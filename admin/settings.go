package admin

import (
	"github.com/gorilla/mux"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"net/http"
)

var loggerSett = logging.NewLogger("web")

// Init - Initialize application
func InitSettingsHandlers(globals *config.Globals, parentRotuer *mux.Route) {
	router := parentRotuer.Subrouter()
	router.HandleFunc("/", SecurityContextHandler(settingsPageHandler, globals, "ADMIN"))
	router.HandleFunc("/setdebug", SecurityContextHandler(setdebugPageHandler, globals, "ADMIN"))
	router.HandleFunc("/confreload", SecurityContextHandler(confReloadPageHandler, globals, "ADMIN"))
}

func settingsPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		LogLevel      int
		Configuration string
	}{
		BasePageContext: bctx,
		LogLevel:        logging.DebugLevel(),
		Configuration:   bctx.Globals.Config.String(),
	}

	RenderTemplateStd(w, ctx, "settings.tmpl")
}

func setdebugPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	r.ParseForm()
	level := ""
	if levels, ok := r.Form["l"]; ok && len(levels) > 0 {
		level = levels[0]
	}
	res := false
	switch level {
	case "0":
		res = logging.SetDebugLevel(0)
		break
	case "1":
		res = logging.SetDebugLevel(1)
		break
	case "2":
		res = logging.SetDebugLevel(2)
		break
	default:
		logging.LogForRequest(loggerSett, r).Warn("setdebugPageHandler missing level", "form", r.Form)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if res {
		logging.LogForRequest(loggerSett, r).Warn("setdebugPageHandler change level", "level", level)
		bctx.AddFlashMessage("Logging level changed", "success")
		bctx.Save()
	}
	http.Redirect(w, r, "/settings/", http.StatusFound)
}

func confReloadPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	bctx.Globals.ReloadConfig()
	bctx.AddFlashMessage("Configuration reloaded", "success")
	bctx.Save()
	http.Redirect(w, r, "/settings/", http.StatusFound)

}
