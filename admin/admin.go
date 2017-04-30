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
	log       = logging.NewLogger("admin")
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
		log.Info("admin.StartAdmin Listen HTTPS; address=%v", globals.Config.AdminPanel.HTTPSAddress)

		go func() {
			if err := http.ListenAndServeTLS(globals.Config.AdminPanel.HTTPSAddress,
				globals.Config.AdminPanel.SslCert, globals.Config.AdminPanel.SslKey, nil); err != nil {
				log.With("err", err).
					Panic("admin.StartAdmin Error listening https; address=%v", globals.Config.AdminPanel.HTTPSAddress)
			}
		}()
	}

	if globals.Config.AdminPanel.HTTPAddress != "" {
		log.Info("admin.StartAdmin Listen; address=%v", globals.Config.AdminPanel.HTTPAddress)

		go func() {
			if err := http.ListenAndServe(globals.Config.AdminPanel.HTTPAddress, nil); err != nil {
				log.With("err", err).
					Panic("admin.StartAdmin Error listening http; address=%v", globals.Config.AdminPanel.HTTPAddress)
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
		log.Warn("GetNamedURL can't find route: %v", name)
		return ""
	}
	rurl, err := route.URL(pairs...)
	if err != nil {
		log.With("err", err).Warn("GetNamedURL can't construct url; name=%v, pairs=%+v", name, pairs)
		return ""
	}
	return rurl.String()
}
