package admin

import (
	"expvar"
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

	for _, ep := range bctx.Globals.GetEndpoints() {
		epname := ep.Name
		all := stats.Get(epname)
		success := stats.Get(epname + "-pass")
		unauth := stats.Get(epname + "-401")
		fail := stats.Get(epname + "-403")
		status := servStat.Get(epname)
		statusSSL := servStat.Get(epname + "-ssl")
		ctx.Stats = append(ctx.Stats, &stat{epname, fail, success, unauth, all, status, statusSSL})
	}

	RenderTemplateStd(w, ctx, "stats.tmpl")
}
