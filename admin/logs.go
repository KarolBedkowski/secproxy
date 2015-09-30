package admin

import (
	"io/ioutil"
	"k.prv/secproxy/logging"
	"net/http"
)

func logsPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Log string
	}{
		BasePageContext: bctx,
	}

	if content, err := ioutil.ReadFile(logging.LogFilename()); err == nil {
		ctx.Log = string(content)
	} else {
		ctx.Log = "Loading log file error: " + err.Error()
	}

	RenderTemplateStd(w, ctx, "logs.tmpl")
}
