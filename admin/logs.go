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
	logFile := logging.LogFilename()

	if logFile == "" {
		ctx.Log = "Loading to file disabled"
	} else if content, err := ioutil.ReadFile(logFile); err == nil {
		ctx.Log = string(content)
	} else {
		ctx.Log = "Loading log file error: " + err.Error()
	}

	renderTemplateStd(w, ctx, "logs.tmpl")
}
