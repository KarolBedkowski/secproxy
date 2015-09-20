package server

import (
	"k.prv/secproxy/config"
	l "k.prv/secproxy/logging"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
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
	rp := httputil.NewSingleHostReverseProxy(uri)
	s := &http.Server{
		Addr:         conf.HTTPAddress,
		Handler:      LogHandler(rp),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		if err := s.ListenAndServe(); err != nil {
			l.Error("server.StartEndpoint starting ", name, " ", err)
		}
	}()
}
