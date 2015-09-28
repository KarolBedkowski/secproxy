package admin

import (
	"io/ioutil"
	"net/http"
)

func logsPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Log string
	}{
		BasePageContext: bctx,
	}

	if content, err := ioutil.ReadFile(bctx.Globals.LogFilename); err == nil {
		ctx.Log = string(content)
	} else {
		ctx.Log = "Loading log file error: " + err.Error()
	}

	RenderTemplateStd(w, ctx, "logs.tmpl")
}
