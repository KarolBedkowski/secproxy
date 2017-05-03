//
// endpoint.go
// Copyright (C) 2017 Karol Będkowski
//
//

package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"k.prv/secproxy/common"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type EndpointStatus int

const (
	EndpointNotExits EndpointStatus = iota
	EndpointNotConfigured
	EndpointStopped
	EndpointStarting
	EndpointStarted
	EndpointStopping
	EndpointError
)

func (s EndpointStatus) String() string {
	switch s {
	case EndpointNotExits:
		return "not exists"
	case EndpointNotConfigured:
		return "not configured"
	case EndpointStopped:
		return "stopped"
	case EndpointStarting:
		return "starting"
	case EndpointStarted:
		return "started"
	case EndpointStopping:
		return "stopping"
	case EndpointError:
		return "error"
	}
	return "unknown"
}

func (s EndpointStatus) canStart() bool {
	return s == EndpointNotExits ||
		s == EndpointStopped ||
		s == EndpointError
}

type proxyEndpoint struct {
	conf    config.EndpointConf
	globals *config.Globals
	llog    logging.Logger

	statusHTTP  EndpointStatus
	statusHTTPS EndpointStatus
	errorHTTP   string
	errorHTTPS  string

	serverHTTPClose  chan bool
	serverHTTPSClose chan bool

	fail      uint32
	success   uint32
	status401 uint32
	status403 uint32
}

func newProxyEndpoint(c config.EndpointConf, g *config.Globals) *proxyEndpoint {
	return &proxyEndpoint{
		conf:    c,
		globals: g,
		llog:    logServer.With("endpoint", c.Name),

		statusHTTP:  EndpointStopped,
		statusHTTPS: EndpointStopped,

		serverHTTPClose:  make(chan bool),
		serverHTTPSClose: make(chan bool),
	}
}

func (p *proxyEndpoint) Update(c config.EndpointConf) {
	p.conf = c
}

func (p *proxyEndpoint) status() (EndpointStatus, EndpointStatus) {
	return p.statusHTTP, p.statusHTTPS
}

func (e *proxyEndpoint) error() (string, string) {
	return e.errorHTTP, e.errorHTTPS
}

func (p *proxyEndpoint) createHandler() (http.Handler, error) {
	uri, err := url.Parse(p.conf.Destination)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %v", p.conf.Destination)
	}

	var handler http.Handler
	revproxy := httputil.NewSingleHostReverseProxy(uri)
	revproxy.ErrorLog = proxyLogger
	handler = http.Handler(revproxy)
	handler = p.authenticationMW(handler)
	handler = common.LogHandler(handler, "server:", map[string]interface{}{"endpoint": p.conf.Name, "module": "server"})
	handler = p.metricsMW(handler)
	return handler, nil
}

func (p *proxyEndpoint) Start() error {
	p.llog.Debug("start")
	handler, err := p.createHandler()
	if err != nil {
		return err
	}

	p.llog.Debug("handler created")

	var errHTTP, errHTTPS error
	if p.conf.HTTPAddress != "" {
		if errHTTP = p.startEndpointHTTP(handler); errHTTP != nil {
			p.llog.With("err", errHTTP).Info("Proxy: start HTTP server error")
			p.statusHTTP = EndpointError
			p.errorHTTP = errHTTP.Error()
		}
	} else {
		p.statusHTTP = EndpointStopped
		p.errorHTTP = ""
	}

	if p.conf.HTTPSAddress != "" {
		if errHTTPS = p.startEndpointHTTPS(handler); errHTTPS != nil {
			p.llog.With("err", errHTTPS).Info("Proxy: start HTTPS server error")
			p.statusHTTPS = EndpointError
			p.errorHTTPS = errHTTPS.Error()
		}
	} else {
		p.statusHTTPS = EndpointStopped
		p.errorHTTPS = ""
	}

	if errHTTP != nil {
		if errHTTPS != nil {
			return fmt.Errorf("HTTP: %s; HTTPS: %s", errHTTP, errHTTPS)
		}
		return fmt.Errorf("HTTP: %s", errHTTP)
	} else if errHTTPS != nil {
		return fmt.Errorf("HTTPS: %s", errHTTPS)
	}

	return nil
}

func (p *proxyEndpoint) Stop() error {
	if p.statusHTTP == EndpointStarted {
		p.llog.Debug("Proxy: stopping http")
		p.serverHTTPClose <- true
	}
	if p.statusHTTPS == EndpointStarted {
		p.llog.Debug("Proxy: stopping https")
		p.serverHTTPSClose <- true
	}
	return nil
}

func (p *proxyEndpoint) startEndpointHTTP(handler http.Handler) error {
	s := &http.Server{
		Addr:         p.conf.HTTPAddress,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	p.llog.Info("Proxy: starting HTTP on %v", s.Addr)
	ls, e := net.Listen("tcp", p.conf.HTTPAddress)
	if e != nil {
		return e
	} else {
		go func() {
			stopChain := p.serverHTTPClose
			go s.Serve(ls)
			p.statusHTTP = EndpointStarted
			p.errorHTTP = ""
			select {
			case <-stopChain:
				ls.Close()
				p.llog.Info("Proxy: stopping HTTP on %v", s.Addr)
				p.statusHTTP = EndpointStopped
				p.errorHTTP = ""
				return
			}
		}()
	}
	return nil
}

func (p *proxyEndpoint) prepareTLS() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		RootCAs:                  p.globals.TLSRootsCAs,
		ClientCAs:                p.globals.TLSRootsCAs,
		PreferServerCipherSuites: true,
	}
	if tlsConfig.NextProtos == nil {
		tlsConfig.NextProtos = []string{"http/1.1"}
	}

	if cert, err := tls.LoadX509KeyPair(p.conf.SslCert, p.conf.SslKey); err != nil {
		return nil, fmt.Errorf("cert error: %s ", err)
	} else {
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}

	if len(p.conf.ClientCertificates) > 0 {
		if certs, err := loadClientCerts(p.conf.ClientCertificates); err != nil {
			return nil, err
		} else {
			tlsConfig.Certificates = append(tlsConfig.Certificates, certs...)
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, cg := range verifiedChains {
				for _, cert := range cg {
					for _, ccert := range tlsConfig.Certificates {
						c := ccert.Leaf
						if c != nil && cert.Equal(c) {
							return nil
						}
					}
				}
			}
			return fmt.Errorf("unknown client certificate")
		}
	}
	return tlsConfig, nil
}

func (p *proxyEndpoint) startEndpointHTTPS(handler http.Handler) error {
	tlsConfig, err := p.prepareTLS()
	if err != nil {
		return fmt.Errorf("prepare tls error: %s", err)
	}

	if ln, err := net.Listen("tcp", p.conf.HTTPSAddress); err != nil {
		p.statusHTTPS = EndpointError
		p.errorHTTPS = err.Error()
		return fmt.Errorf("starting https error: %s ", err)
	} else {
		tlsListener := tls.NewListener(ln, tlsConfig)
		s := &http.Server{
			Addr:         p.conf.HTTPSAddress,
			Handler:      handler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		p.llog.Info("Proxy: starting HTTPS on %s", s.Addr)
		go func() {
			stopChain := p.serverHTTPSClose
			go s.Serve(tlsListener)
			p.statusHTTPS = EndpointStarted
			p.errorHTTPS = ""
			select {
			case <-stopChain:
				ln.Close()
				p.llog.Info("Proxy: stopping HTTPS on %v", s.Addr)
				p.statusHTTPS = EndpointStopped
				p.errorHTTPS = ""
				return
			}
		}()
	}
	return nil
}

func (p *proxyEndpoint) authenticationMW(h http.Handler) http.Handler {
	var networks []*net.IPNet
	if p.conf.AcceptAddr != "" {
		networks = prepareNetworks(p.conf.AcceptAddr)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := p.llog.WithRequest(r)
		if networks != nil {
			if !acceptAddress(networks, r.RemoteAddr) {
				l.Info("Proxy: authenticationMW 403 Forbidden - addr")
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				atomic.AddUint32(&p.status403, 1)
				return
			}
		}

		if len(p.conf.Users) == 0 {
			h.ServeHTTP(w, r)
			return
		}
		usr, pass, _ := r.BasicAuth()
		if usr == "" && r.URL != nil && r.URL.User != nil {
			usr = r.URL.User.Username()
			pass, _ = r.URL.User.Password()
		}

		if usr == "" {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"SecProxy\"")
			l.With("status", 401).Info("Proxy: authenticationMW 401 Unauthorized")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			atomic.AddUint32(&p.status401, 1)
			return
		}

		user := p.globals.GetUser(usr)
		if user.Active && p.conf.AcceptUser(user.Login) && user.CheckPassword(pass) {
			l.With("user", user.Login).Debug("User authenticated")
			r.Header.Set("X-Authenticated-User", usr)
			atomic.AddUint32(&p.success, 1)
			h.ServeHTTP(w, r)
			return
		}
		//log.Info("authenticationMW ", endpoint, " 403 Forbidden")
		//http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		atomic.AddUint32(&p.status401, 1)

		w.Header().Set("WWW-Authenticate", "Basic realm=\"REALM\"")
		l.With("user", user.Login).With("user_active", user.Active).
			With("status", 401).
			Info("Proxy: authenticationMW 401 Unauthorized")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	})
}

func (p *proxyEndpoint) metricsMW(h http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()

		writer := &common.ResponseWriter{ResponseWriter: w, Status: 200}

		defer func() {
			elapsed := float64(time.Since(now)) / float64(time.Second)
			method := strings.ToLower(r.Method)
			code := strconv.Itoa(writer.Status)
			group := groupStatusCode(writer.Status)
			port := r.URL.Port()
			metricReqCnt.WithLabelValues(method, code, group, p.conf.Name, port).Inc()
			metricReqDur.WithLabelValues(method, code, group, p.conf.Name, port).Observe(elapsed)
		}()

		h.ServeHTTP(writer, r)
	})
}

type EndpointInfo struct {
	Endpoint    string
	Fail        uint
	Success     uint
	Status401   uint
	Status403   uint
	Total       uint
	StatusHTTP  string
	StatusHTTPS string
	ErrorHTTP   string
	ErrorHTTPS  string
}

func (p *proxyEndpoint) Info() *EndpointInfo {
	return &EndpointInfo{
		Endpoint:    p.conf.Name,
		Fail:        uint(p.fail),
		Success:     uint(p.success),
		Status401:   uint(p.status401),
		Status403:   uint(p.status403),
		Total:       uint(p.fail + p.success + p.status401 + p.status403),
		StatusHTTP:  p.statusHTTP.String(),
		StatusHTTPS: p.statusHTTPS.String(),
		ErrorHTTP:   p.errorHTTP,
		ErrorHTTPS:  p.errorHTTPS,
	}
}
