package admin

import (
	"github.com/gorilla/mux"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"k.prv/secproxy/proxy"
	"net/http"
)

var logEP = logging.NewLogger("admin.auth")

// Init - Initialize application
func InitEndpointsHandlers(globals *config.Globals, parentRotuer *mux.Route) {
	router := parentRotuer.Subrouter()
	router.HandleFunc("/", SecurityContextHandler(endpointsPageHandler, globals, "ADMIN"))
	router.HandleFunc("/endpoint/", SecurityContextHandler(endpointPageHandler, globals, "ADMIN"))
	router.HandleFunc("/endpoint/{name}", SecurityContextHandler(endpointPageHandler, globals, "ADMIN"))
	router.HandleFunc("/endpoint/{name}/{action}", SecurityContextHandler(endpointActionPageHandler, globals, "ADMIN"))
}

type endpoint struct {
	Name        string
	StatusHTTP  string
	StatusHTTPS string
	LocalHTTP   string
	LocalHTTPS  string
	Remote      string
	ErrorHTTP   string
	ErrorHTTPS  string
	Running     bool
}

func endpointsPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Endpoints []*endpoint
	}{
		BasePageContext: bctx,
	}
	for _, ep := range bctx.Globals.GetEndpoints() {
		statusHTTP, statusHTTPS, running := proxy.EndpointRunning(ep.Name)
		errorHTTP, errorHTTPS := proxy.EndpointErrors(ep.Name)
		ctx.Endpoints = append(ctx.Endpoints,
			&endpoint{
				Name:        ep.Name,
				StatusHTTP:  statusHTTP,
				StatusHTTPS: statusHTTPS,
				Running:     running,
				LocalHTTP:   ep.HTTPAddress,
				LocalHTTPS:  ep.HTTPSAddress,
				Remote:      ep.Destination,
				ErrorHTTP:   errorHTTP,
				ErrorHTTPS:  errorHTTPS,
			})
	}
	RenderTemplateStd(w, ctx, "endpoints/index.tmpl")
}

type endpointForm struct {
	*config.EndpointConf
	Errors map[string]string `schema:"-"`
}

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

// HasCCert check is certificate `name` in in client certificates list
func (f *endpointForm) HasCCert(name string) bool {
	for _, u := range f.ClientCertificates {
		if u == name {
			return true
		}
	}
	return false
}

func endpointPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Form     endpointForm
		AllUsers []*config.User
		Certs    []string
		Keys     []string
	}{
		BasePageContext: bctx,
		AllUsers:        bctx.Globals.GetUsers(),
		Certs:           bctx.Globals.FindCerts(),
		Keys:            bctx.Globals.FindKeys(),
	}
	ctx.Form.EndpointConf = &config.EndpointConf{}

	vars := mux.Vars(r)
	epname := ""
	if name, ok := vars["name"]; ok {
		epname = name
	}
	log := logEP.WithRequest(r).With("user", bctx.UserLogin()).With("endpoint", epname)

	switch r.Method {
	case "POST":
		r.ParseForm()
		if err := decoder.Decode(&ctx.Form, r.Form); err != nil {
			log.With("err", err).
				Info("Endpoint edit: decode form error; form=%+v", r.Form)
			break
		}

		if errors := ctx.Form.Validate(bctx.Globals, epname == ""); len(errors) > 0 {
			ctx.Form.Errors = errors
			break
		}

		bctx.Globals.SaveEndpoint(ctx.Form.EndpointConf)
		ctx.AddFlashMessage("Endpoint saved", "success")
		ctx.Save()
		log.Info("Endpoint edit: saved")
		http.Redirect(w, r, "/endpoints/", http.StatusFound)
		return
	case "GET":
		if epname != "" {
			if ep := bctx.Globals.GetEndpoint(epname); ep != nil {
				ctx.Form.EndpointConf = ep.Clone()
			} else {
				log.Info("Endpoint edit: endpoint %v not found", epname)
				http.Error(w, "Endpoint not found", http.StatusNotFound)
				return
			}
		}
	}

	ctx.Save()
	RenderTemplateStd(w, ctx, "endpoints/endpoint.tmpl")
}

func endpointActionPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	vars := mux.Vars(r)
	epname := vars["name"]
	action := vars["action"]
	log := logEP.WithRequest(r).With("user", bctx.UserLogin()).
		With("endpoint", epname).With("action", action)

	if epname == "" || action == "" {
		log.Debug("Endpoint action: missing arguments")
		http.Error(w, "Wrong arguments", http.StatusBadRequest)
		return
	}

	switch action {
	case "start":
		if err := proxy.StartEndpoint(epname, bctx.Globals); err == nil {
			bctx.AddFlashMessage("Endpoint started", "success")
		} else {
			bctx.AddFlashMessage("Endpoint failed to start: "+err.Error(), "error")
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
		log.Info("Endpoint action: invalid action=%v", action)
		http.Error(w, "Endpoint not found", http.StatusBadRequest)
		return
	}

	bctx.Save()
	http.Redirect(w, r, "/endpoints/", http.StatusFound)
	return
}
