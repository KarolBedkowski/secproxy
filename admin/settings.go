package admin

import (
	"github.com/gorilla/mux"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"net/http"
)

// Init - Initialize application
func InitSettingsHandlers(globals *config.Globals, parentRotuer *mux.Route) {
	router := parentRotuer.Subrouter()
	router.HandleFunc("/", SecurityContextHandler(settingsPageHandler, globals, "ADMIN"))
	router.HandleFunc("/setdebug", SecurityContextHandler(setdebugPageHandler, globals, "ADMIN"))
}

func settingsPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		LogLevel int
	}{
		BasePageContext: bctx,
		LogLevel:        logging.DebugLevel(),
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
		logging.LogForRequest(logCerts, r).Warn("setdebugPageHandler missing level", "form", r.Form)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if res {
		bctx.AddFlashMessage("Logging level changed", "success")
		bctx.Save()
	}
	http.Redirect(w, r, "/settings/", http.StatusFound)
}
