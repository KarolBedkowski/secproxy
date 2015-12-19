package admin

import (
	"github.com/gorilla/mux"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"k.prv/secproxy/proxy"
	"net/http"
	"strings"
)

var logEP = logging.NewLogger("admin.auth")

// Init - Initialize application
func InitEndpointsHandlers(globals *config.Globals, parentRotuer *mux.Route) {
	router := parentRotuer.Subrouter()
	router.HandleFunc("/", SecurityContextHandler(endpointsPageHandler, globals, "ADMIN"))
	router.HandleFunc("/{name}", SecurityContextHandler(endpointPageHandler, globals, "ADMIN"))
	router.HandleFunc("/{name}/{action}", SecurityContextHandler(endpointActionPageHandler, globals, "ADMIN"))
}

type endpoint struct {
	Name       string
	Running    bool
	Local      string
	LocalHTTPS string
	remote     string
	Errors     string
}

func endpointsPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Endpoints []*endpoint
	}{
		BasePageContext: bctx,
	}
	for _, ep := range bctx.Globals.GetEndpoints() {
		ctx.Endpoints = append(ctx.Endpoints,
			&endpoint{
				ep.Name,
				proxy.EndpointRunning(ep.Name),
				ep.HTTPAddress,
				ep.HTTPSAddress,
				ep.Destination,
				proxy.EndpointErrors(ep.Name),
			})
	}
	RenderTemplateStd(w, ctx, "endpoints/index.tmpl")
}

type (
	endpointForm struct {
		*config.EndpointConf
		Errors map[string]string `schema:"-"`
	}
)

func (f *endpointForm) Validate(globals *config.Globals, newEp bool) (errors map[string]string) {
	errors = f.EndpointConf.Validate()
	return
}

func (f *endpointForm) HasUser(name string) bool {
	for _, u := range f.EndpointConf.Users {
		if u == name {
			return true
		}
	}
	return false
}

func endpointPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	vars := mux.Vars(r)
	ctx := &struct {
		*BasePageContext
		Form     endpointForm
		AllUsers []*config.User
		Certs    []string
	}{
		BasePageContext: bctx,
		AllUsers:        bctx.Globals.GetUsers(),
		Certs:           bctx.Globals.FindCerts(),
	}
	if r.Method == "POST" && r.FormValue("_method") != "" {
		r.Method = r.FormValue("_method")
	}
	epname, ok := vars["name"]
	if !ok || epname == "" {
		logging.LogForRequest(logEP, r).Error("admin.endpointPageHandler missing name", "vars", vars)
		http.Error(w, "Missing name", http.StatusBadRequest)
		return
	}

	newEp := epname == "<new>"

	if !newEp {
		if ep := bctx.Globals.GetEndpoint(epname); ep != nil {
			ctx.Form.EndpointConf = ep.Clone()
		} else {
			logging.LogForRequest(logEP, r).Error("admin.endpointPageHandler ep not found", "endpoint", epname)
			http.Error(w, "Endpoint not found", http.StatusNotFound)
			return
		}
	} else {
		ctx.Form.EndpointConf = &config.EndpointConf{}
	}
	switch r.Method {
	case "POST":
		r.ParseForm()
		if err := decoder.Decode(&ctx.Form, r.Form); err != nil {
			logging.LogForRequest(logEP, r).Error("admin.endpointPageHandler decode form error", "err", err, "form", r.Form)
			break
		}
		if errors := ctx.Form.Validate(bctx.Globals, newEp); len(errors) > 0 {
			ctx.Form.Errors = errors
			break
		}
		bctx.Globals.SaveEndpoint(ctx.Form.EndpointConf)
		ctx.AddFlashMessage("Endpoint saved", "success")
		ctx.Save()
		http.Redirect(w, r, "/endpoints/", http.StatusFound)
		return
	}
	ctx.Save()
	RenderTemplateStd(w, ctx, "endpoints/endpoint.tmpl")

}

func endpointActionPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	vars := mux.Vars(r)
	epname, ok := vars["name"]
	if !ok || epname == "" {
		logging.LogForRequest(logEP, r).Error("admin.endpointActionPageHandler missing name", "vars", vars)
		http.Error(w, "Missing name", http.StatusBadRequest)
		return
	}

	action, ok := vars["action"]
	if !ok || action == "" {
		logging.LogForRequest(logEP, r).Error("admin.endpointActionPageHandler missing action", "vars", vars)
		http.Error(w, "Missing action", http.StatusBadRequest)
		return
	}

	switch action {
	case "start":
		err := proxy.StartEndpoint(epname, bctx.Globals)
		if len(err) == 0 {
			bctx.AddFlashMessage("Endpoint started", "success")
		} else {
			bctx.AddFlashMessage("Endpoint failed to start: "+strings.Join(err, ", "), "error")
		}
		break
	case "stop":
		proxy.StopEndpoint(epname)
		bctx.AddFlashMessage("Endpoint stopped", "success")
		break
	case "delete":
		proxy.StopEndpoint(epname)
		bctx.Globals.DeleteEndpoint(epname)
		bctx.AddFlashMessage("Endpoint deleted", "success")
		break
	default:
		logging.LogForRequest(logEP, r).Warn("admin.endpointActionPageHandler invalid action", "action", action)
	}
	bctx.Save()
	http.Redirect(w, r, "/endpoints/", http.StatusFound)
	return
}
