package admin

import (
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
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

	debug := logging.DebugLevel() > 0

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

	http.Handle("/static/", http.StripPrefix("/static",
		FileServer(http.Dir(globals.Config.AdminPanel.StaticDir), debug)))
	http.Handle("/favicon.ico", FileServer(http.Dir(globals.Config.AdminPanel.StaticDir), debug))

	http.Handle("/", globals.StatsAdmin.Handler(common.LogHandler(CsrfHandler(SessionHandler(appRouter)), "admin:", "module", "admin")))

	if globals.Config.AdminPanel.HTTPSAddress != "" {
		log.Info("admin.StartAdmin Listen HTTPS ", "port", globals.Config.AdminPanel.HTTPSAddress)

		go func() {
			if err := http.ListenAndServeTLS(globals.Config.AdminPanel.HTTPSAddress,
				globals.Config.AdminPanel.SslCert, globals.Config.AdminPanel.SslKey, nil); err != nil {
				log.Error("admin.StartAdmin Error listening https, ", "err", err)
			}
		}()
	}

	if globals.Config.AdminPanel.HTTPAddress != "" {
		log.Info("admin.StartAdmin Listen", "port", globals.Config.AdminPanel.HTTPAddress)

		go func() {
			if err := http.ListenAndServe(globals.Config.AdminPanel.HTTPAddress, nil); err != nil {
				log.Error("admin.StartAdmin Error listening http, ", "err", err)
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
		log.Error("GetNamedURL error", "name", name)
		return ""
	}
	rurl, err := route.URL(pairs...)
	if err != nil {
		log.Error("GetNamedURL error", "name", name, "err", err.Error())
		return ""
	}
	return rurl.String()
}
