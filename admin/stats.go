package admin

import (
	"expvar"
	"github.com/gorilla/mux"
	"k.prv/secproxy/config"
	"net/http"
)

type stat struct {
	Endpoint     string
	Fail         interface{}
	Success      interface{}
	Unauthorized interface{}
	All          interface{}
	Status       interface{}
	StatusSSL    interface{}
	Error        interface{}
	ErrorSSL     interface{}
}

// Init - Initialize application
func InitStatsHandlers(globals *config.Globals, parentRotuer *mux.Route) {
	router := parentRotuer.Subrouter()
	router.HandleFunc("/", SecurityContextHandler(statsPageHandler, globals, ""))
}

func statsPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Stats []*stat
	}{
		BasePageContext: bctx,
		Stats:           []*stat{},
	}

	var stats *expvar.Map
	stats = expvar.Get("counters").(*expvar.Map)
	servStat := expvar.Get("states").(*expvar.Map)
	errors := expvar.Get("errors").(*expvar.Map)

	for _, ep := range bctx.Globals.GetEndpoints() {
		epname := ep.Name
		all := stats.Get(epname)
		success := stats.Get(epname + "|pass")
		unauth := stats.Get(epname + "|401")
		fail := stats.Get(epname + "|403")
		status := servStat.Get(epname)
		statusSSL := servStat.Get(epname + "|ssl")
		err := errors.Get(epname)
		errSSL := errors.Get(epname + "|ssl")
		ctx.Stats = append(ctx.Stats, &stat{epname, fail, success, unauth, all, status, statusSSL,
			err, errSSL})
	}

	RenderTemplateStd(w, ctx, "stats.tmpl")
}
