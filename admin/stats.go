package admin

import (
	"github.com/gorilla/mux"
	"k.prv/secproxy/config"
	"k.prv/secproxy/proxy"
	"net/http"
)

// Init - Initialize application
func initStatsHandlers(globals *config.Globals, parentRotuer *mux.Route) {
	router := parentRotuer.Subrouter()
	router.HandleFunc("/", securityContextHandler(statsPageHandler, globals, ""))
}

func statsPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Stats []*proxy.EndpointInfo
	}{
		BasePageContext: bctx,
		Stats:           proxy.EndpointsInfo(),
	}

	renderTemplateStd(w, ctx, "stats.tmpl")
}
