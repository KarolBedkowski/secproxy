package server

import (
	"k.prv/secproxy/config"
	l "k.prv/secproxy/logging"
	"k.prv/secproxy/common"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
	"expvar"
)

type (
	state struct {
		running     bool
		serverClose chan bool
	}
)

var (
	states map[string]*state = make(map[string]*state)
	counters = expvar.NewMap("counters")
)

func Init(globals *config.Globals) {
}

func StartEndpoint(name string, globals *config.Globals) {
	l.Info("server.StartEndpoint starting ", name)
	conf := globals.Endpoints.Endpoints[name]
	uri, err := url.Parse(conf.Destination)
	if err != nil {
		return
	}
	st := &state{
		serverClose: make(chan bool),
	}
	states[name] = st

	var handler http.Handler

	handler = httputil.NewSingleHostReverseProxy(uri)
	if len(conf.Users) > 0 {
		handler = authenticationMW(handler, name, globals)
	}
	handler = common.LogHandler(handler)

	s := &http.Server{
		Addr:         conf.HTTPAddress,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	ls, e := net.Listen("tcp", conf.HTTPAddress)
	if e != nil {
		l.Panic(e.Error())
	}
	go func() {
		st.running = true
		go s.Serve(ls)
		select {
		case <-st.serverClose:
			l.Info("server.StartEndpoint stop ", name)
			ls.Close()
			st.running = false
			return
		}
	}()
}

func StopEndpoint(name string, globals *config.Globals) {
	l.Info("server.StopEndpoint ", name)
	states[name].serverClose <- true
}

func authenticationMW(h http.Handler, endpoint string, globals *config.Globals) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counters.Add(endpoint, 1)
		usr, pass, _ := r.BasicAuth()
		if usr == "" && r.URL != nil && r.URL.User != nil {
			usr = r.URL.User.Username()
			pass, _ = r.URL.User.Password()
		}

		if usr == "" {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"REALM\"")
			l.Info("authenticationMW ", endpoint, " 401 Unauthorized")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			counters.Add(endpoint + "-401", 1)
			return
		}

		user := globals.GetUser(usr)
		if user.CheckPassword(pass) {
			r.Header.Set("X-Authenticated-User", usr)
			counters.Add(endpoint + "-pass", 1)
			h.ServeHTTP(w, r)
			return
		}
		l.Info("authenticationMW ", endpoint, " 403 Forbidden")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		counters.Add(endpoint + "-403", 1)
	})
}
