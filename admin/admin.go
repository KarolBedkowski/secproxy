package admin

import (
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/prometheus/client_golang/prometheus"
	"k.prv/secproxy/common"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"net/http"
)

var (
	appRouter = mux.NewRouter()
	decoder   = schema.NewDecoder()
	logAdmin  = logging.NewLogger("admin")
)

func StartAdmin(globals *config.Globals) {
	InitSessionStore(globals.Config)
	appRouter.HandleFunc("/", SecurityContextHandler(mainPageHandler, globals, ""))

	appRouter.HandleFunc("/login", ContextHandler(loginPageHandler, globals)).Name("auth-login")
	appRouter.HandleFunc("/logout", logoffHandler)
	appRouter.HandleFunc("/chpass", SecurityContextHandler(chpassPageHandler, globals, ""))
	appRouter.HandleFunc("/logs", SecurityContextHandler(logsPageHandler, globals, "ADMIN"))

	InitUsersHandlers(globals, appRouter.PathPrefix("/users"))
	InitEndpointsHandlers(globals, appRouter.PathPrefix("/endpoints"))
	InitCertsHandlers(globals, appRouter.PathPrefix("/certs"))
	InitStatsHandlers(globals, appRouter.PathPrefix("/stats"))
	InitSettingsHandlers(globals, appRouter.PathPrefix("/settings"))

	http.Handle("/static/", prometheus.InstrumentHandler(
		"static",
		http.StripPrefix(
			"/static",
			FileServer(http.Dir(globals.Config.AdminPanel.StaticDir),
				globals.DevMode))))
	http.Handle("/favicon.ico",
		FileServer(http.Dir(globals.Config.AdminPanel.StaticDir),
			globals.DevMode))

	http.Handle("/", prometheus.InstrumentHandlerFunc("appRouter",
		common.LogHandler(
			CsrfHandler(
				SessionHandler(appRouter)),
			"admin:", map[string]interface{}{"module": "admin"})))
	http.Handle("/metrics", prometheus.Handler())

	if globals.Config.AdminPanel.HTTPSAddress != "" {
		logAdmin.Info("Starting admin panel on https %v", globals.Config.AdminPanel.HTTPSAddress)

		go func() {
			if err := http.ListenAndServeTLS(globals.Config.AdminPanel.HTTPSAddress,
				globals.Config.AdminPanel.SslCert, globals.Config.AdminPanel.SslKey, nil); err != nil {
				logAdmin.With("err", err).
					Panic("ERROR: start listen on HTTPS failed; address=%v", globals.Config.AdminPanel.HTTPSAddress)
			}
		}()
	}

	if globals.Config.AdminPanel.HTTPAddress != "" {
		logAdmin.Info("Starting admin panel on http %v", globals.Config.AdminPanel.HTTPAddress)

		go func() {
			if err := http.ListenAndServe(globals.Config.AdminPanel.HTTPAddress, nil); err != nil {
				logAdmin.With("err", err).
					Panic("ERROR: start listen on HTTP failed; address=%v", globals.Config.AdminPanel.HTTPAddress)
			}
		}()
	}
}

func mainPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	//	RenderTemplateStd(w, bctx, "index.tmpl")
	http.Redirect(w, r, "/stats/", http.StatusFound)
}

// GetNamedURL - Return url for named route and parameters
func GetNamedURL(name string, pairs ...string) (url string) {
	route := appRouter.Get(name)
	if route == nil {
		logAdmin.Warn("ERROR: GetNamedURL can't find route: %v", name)
		return ""
	}
	rurl, err := route.URL(pairs...)
	if err != nil {
		logAdmin.With("err", err).
			Warn("ERROR: GetNamedURL can't construct url; name=%v, pairs=%+v", name, pairs)
		return ""
	}
	return rurl.String()
}
