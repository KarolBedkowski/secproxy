package server

import (
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
		running bool
		serverClose chan bool
	}
)

var (
	states map[string]*state = make(map[string]*state)
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

	rp := httputil.NewSingleHostReverseProxy(uri)
	s := &http.Server{
		Addr:         conf.HTTPAddress,
		Handler:      LogHandler(rp),
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
