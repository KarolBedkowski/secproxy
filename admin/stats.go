package admin

import (
	"net/http"
	"expvar"
)


type stat struct {
	Endpoint string
	Fail interface{}
	Success interface{}
	Unauthorized interface{}
	All	interface{}
}

func statsPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Stats []*stat
	}{
		BasePageContext: bctx,
		Stats: []*stat{},
	}
	
	var stats *expvar.Map
	stats = expvar.Get("counters").(*expvar.Map)

	for epname := range bctx.Globals.Endpoints.Endpoints {
		all := stats.Get(epname)
		success := stats.Get(epname + "-pass")
		unauth := stats.Get(epname + "-401")
		fail := stats.Get(epname + "-403")
		ctx.Stats = append(ctx.Stats, &stat{epname, fail, success, unauth, all})
	}

	RenderTemplateStd(w, ctx, "stats.tmpl")
}
