package server

import (
	"expvar"
	"k.prv/secproxy/common"
	"k.prv/secproxy/config"
	l "k.prv/secproxy/logging"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

type (
	state struct {
		running     bool
		serverClose chan bool
	}

	varState string
)

func (v varState) String() string {
	return string(v)
}

var (
	states   map[string]*state = make(map[string]*state)
	counters                   = expvar.NewMap("counters")
	servStat                   = expvar.NewMap("states")
)

func Init(globals *config.Globals) {
}

func StartEndpoint(name string, globals *config.Globals) (errstr string) {
	l.Info("server.StartEndpoint starting ", name)
	if st, ok := states[name]; ok {
		if st.running {
			l.Warn("server.StartEndpoint already started ", name)
			return "already running"
		}
	}

	servStat.Set(name, varState("stopped"))
	conf := globals.GetEndpoint(name)
	if conf == nil {
		return "invalid endpoint"
	}
	uri, err := url.Parse(conf.Destination)
	if err != nil {
		return "invalid url"
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
	handler = counterMw(handler, name)
	handler = common.LogHandler(handler)

	s := &http.Server{
		Addr:         conf.HTTPAddress,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	ls, e := net.Listen("tcp", conf.HTTPAddress)
	if e != nil {
		return "listen error " + e.Error()
	}
	go func() {
		st.running = true
		go s.Serve(ls)
		servStat.Set(name, varState("running"))
		select {
		case <-st.serverClose:
			l.Info("server.StartEndpoint stop ", name)
			ls.Close()
			st.running = false
			servStat.Set(name, varState("stopped"))
			return
		}
	}()
	return ""
}

func StopEndpoint(name string) {
	l.Info("server.StopEndpoint ", name)
	states[name].serverClose <- true
}

func EndpointRunning(name string) bool {
	if st, ok := states[name]; ok {
		return st.running
	}
	return false
}

func counterMw(h http.Handler, endpoint string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counters.Add(endpoint, 1)
		h.ServeHTTP(w, r)
	})
}

func authenticationMW(h http.Handler, endpoint string, globals *config.Globals) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		usr, pass, _ := r.BasicAuth()
		if usr == "" && r.URL != nil && r.URL.User != nil {
			usr = r.URL.User.Username()
			pass, _ = r.URL.User.Password()
		}

		if usr == "" {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"REALM\"")
			l.Info("authenticationMW ", endpoint, " 401 Unauthorized")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			counters.Add(endpoint+"-401", 1)
			return
		}

		user := globals.GetUser(usr)
		if user.CheckPassword(pass) {
			r.Header.Set("X-Authenticated-User", usr)
			counters.Add(endpoint+"-pass", 1)
			h.ServeHTTP(w, r)
			return
		}
		l.Info("authenticationMW ", endpoint, " 403 Forbidden")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		counters.Add(endpoint+"-403", 1)
	})
}
