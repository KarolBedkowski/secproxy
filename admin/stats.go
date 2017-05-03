package admin

import (
	"github.com/gorilla/mux"
	"k.prv/secproxy/config"
	"k.prv/secproxy/proxy"
	"net/http"
)

// Init - Initialize application
func InitStatsHandlers(globals *config.Globals, parentRotuer *mux.Route) {
	router := parentRotuer.Subrouter()
	router.HandleFunc("/", SecurityContextHandler(statsPageHandler, globals, ""))
}

func statsPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Stats []*proxy.EndpointInfo
	}{
		BasePageContext: bctx,
		Stats:           proxy.EndpointsInfo(),
	}

	RenderTemplateStd(w, ctx, "stats.tmpl")
}
