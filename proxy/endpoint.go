//
// endpoint.go
// Copyright (C) 2017 Karol Będkowski
//

package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"k.prv/secproxy/common"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EndpointStatus define current endpoint status
type EndpointStatus int

const (
	// EndpointStopped - endpoint is not running (stopped)
	EndpointStopped EndpointStatus = iota
	// EndpointStarted - endpoint is active
	EndpointStarted
	// EndpointError - endpoint is not running because of some error
	EndpointError
)

func (s EndpointStatus) String() string {
	switch s {
	case EndpointStopped:
		return "stopped"
	case EndpointStarted:
		return "started"
	case EndpointError:
		return "error"
	}
	return "unknown"
}

func (s EndpointStatus) canStart() bool {
	return s == EndpointStopped || s == EndpointError
}

// EndpointInfo represent endpoint status exported by Info
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

type proxyEndpoint struct {
	conf    *config.EndpointConf
	globals *config.Globals
	llog    logging.Logger

	statusHTTP  EndpointStatus
	statusHTTPS EndpointStatus
	errorHTTP   string
	errorHTTPS  string

	httpListener  net.Listener
	httpsListener net.Listener

	// counters
	statusFail uint32
	statusOk   uint32
	status401  uint32
	status403  uint32

	mu sync.RWMutex
}

func newProxyEndpoint(c *config.EndpointConf, g *config.Globals) *proxyEndpoint {
	return &proxyEndpoint{
		conf:    c.Clone(),
		globals: g,
		llog:    logServer.With("endpoint", c.Name),

		statusHTTP:  EndpointStopped,
		statusHTTPS: EndpointStopped,
	}
}

// Update endpoint configuration.
// Endpoint normally should be stopped
func (p *proxyEndpoint) update(c *config.EndpointConf) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.conf = c.Clone()
}

func (p *proxyEndpoint) status() (EndpointStatus, EndpointStatus) {
	return p.statusHTTP, p.statusHTTPS
}

func (p *proxyEndpoint) error() (string, string) {
	return p.errorHTTP, p.errorHTTPS
}

func (p *proxyEndpoint) info() *EndpointInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return &EndpointInfo{
		Endpoint:    p.conf.Name,
		Fail:        uint(p.statusFail),
		Success:     uint(p.statusOk),
		Status401:   uint(p.status401),
		Status403:   uint(p.status403),
		Total:       uint(p.statusFail + p.statusOk + p.status401 + p.status403),
		StatusHTTP:  p.statusHTTP.String(),
		StatusHTTPS: p.statusHTTPS.String(),
		ErrorHTTP:   p.errorHTTP,
		ErrorHTTPS:  p.errorHTTPS,
	}
}

// Start endpoint
func (p *proxyEndpoint) start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.llog.Info("Proxy: starting endpoint %v", p.conf.Name)
	p.errorHTTP = ""
	p.errorHTTPS = ""
	p.statusHTTP = EndpointStopped
	p.statusHTTPS = EndpointStopped

	handler, err := p.createHandler()
	if err != nil {
		p.llog.Debug("ERROR: handler create error: %s", err)
		return err
	}

	p.llog.Debug("handler created")

	var errHTTP, errHTTPS error
	if p.conf.HTTPAddress != "" && p.statusHTTP == EndpointStopped {
		if errHTTP = p.startEndpointHTTP(handler); errHTTP != nil {
			p.llog.With("err", errHTTP).Info("ERROR: Proxy: start HTTP server error")
			p.statusHTTP = EndpointError
			p.errorHTTP = errHTTP.Error()
		} else {
			p.llog.Info("Proxy: http endpoint %v started", p.conf.Name)
		}
	}

	if p.conf.HTTPSAddress != "" && p.statusHTTPS == EndpointStopped {
		if errHTTPS = p.startEndpointHTTPS(handler); errHTTPS != nil {
			p.llog.With("err", errHTTPS).Info("ERROR: Proxy: start HTTPS server error")
			p.statusHTTPS = EndpointError
			p.errorHTTPS = errHTTPS.Error()
		} else {
			p.llog.Info("Proxy: https endpoint %v started", p.conf.Name)
		}
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

func (p *proxyEndpoint) stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.statusHTTP == EndpointStarted && p.httpListener != nil {
		p.llog.Info("Proxy: stopping HTTP")
		p.httpListener.Close()
		p.httpListener = nil
	}
	p.statusHTTP = EndpointStopped

	if p.statusHTTPS == EndpointStarted && p.httpsListener != nil {
		p.llog.Debug("Proxy: stopping HTTPS")
		p.httpsListener.Close()
		p.httpsListener = nil
	}
	p.statusHTTPS = EndpointStopped

	return nil
}

func (p *proxyEndpoint) createHandler() (http.Handler, error) {
	uri, err := url.Parse(p.conf.Destination)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %v", p.conf.Destination)
	}

	revproxy := httputil.NewSingleHostReverseProxy(uri)
	revproxy.ErrorLog = proxyLogger
	handler := http.Handler(revproxy)
	handler = p.authenticationMW(handler)
	handler = common.LogHandler(handler, "Proxy:",
		map[string]interface{}{"endpoint": p.conf.Name})
	handler = p.metricsMW(handler)
	return handler, nil
}

func (p *proxyEndpoint) startEndpointHTTP(handler http.Handler) error {
	p.llog.Info("Proxy: starting HTTP on %v", p.conf.HTTPAddress)

	if p.httpListener != nil {
		p.llog.Warn("httpListener already exists; closing before start")
		p.httpListener.Close()
		p.httpListener = nil
	}

	var err error
	p.httpListener, err = net.Listen("tcp", p.conf.HTTPAddress)
	if err != nil {
		return err
	}

	s := &http.Server{
		Addr:         p.conf.HTTPAddress,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go s.Serve(p.httpListener)
	p.statusHTTP = EndpointStarted

	return nil
}

// tlsConfigWC is tlsConfigWC with certificate verification function
type tlsConfigWC tls.Config

func (t *tlsConfigWC) verifyCers(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	for _, cg := range verifiedChains {
		for _, cert := range cg {
			for _, ccert := range t.Certificates {
				c := ccert.Leaf
				if c != nil && cert.Equal(c) {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("unknown client certificate")
}

func (p *proxyEndpoint) prepareTLS() (*tlsConfigWC, error) {
	tlsConfig := &tlsConfigWC{
		RootCAs:                  p.globals.TLSRootsCAs,
		ClientCAs:                p.globals.TLSRootsCAs,
		PreferServerCipherSuites: true,
	}
	if tlsConfig.NextProtos == nil {
		tlsConfig.NextProtos = []string{"http/1.1"}
	}

	cert, err := tls.LoadX509KeyPair(p.conf.SslCert, p.conf.SslKey)
	if err != nil {
		return nil, err
	}

	tlsConfig.Certificates = append(tlsConfig.Certificates, cert)

	if len(p.conf.ClientCertificates) > 0 {
		certs, err := loadClientCerts(p.conf.ClientCertificates)
		if err != nil {
			return nil, err
		}

		tlsConfig.Certificates = append(tlsConfig.Certificates, certs...)
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		// client certificates verification function
		tlsConfig.VerifyPeerCertificate = tlsConfig.verifyCers
	}
	return tlsConfig, nil
}

func (p *proxyEndpoint) startEndpointHTTPS(handler http.Handler) error {
	p.llog.Info("Proxy: starting HTTPS on %s", p.conf.HTTPSAddress)

	if p.httpsListener != nil {
		p.llog.Warn("httpsListener already exists; closing")
		p.httpsListener.Close()
		p.httpsListener = nil
	}

	tlsConfig, err := p.prepareTLS()
	if err != nil {
		return fmt.Errorf("prepare tls error: %s", err)
	}

	p.httpsListener, err = net.Listen("tcp", p.conf.HTTPSAddress)
	if err != nil {
		p.statusHTTPS = EndpointError
		p.errorHTTPS = err.Error()
		return fmt.Errorf("starting https error: %s ", err)
	}

	s := &http.Server{
		Addr:         p.conf.HTTPSAddress,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go s.Serve(tls.NewListener(p.httpsListener, (*tls.Config)(tlsConfig)))
	p.statusHTTPS = EndpointStarted
	return nil
}

func (p *proxyEndpoint) authenticationMW(h http.Handler) http.Handler {
	var networks []*net.IPNet
	if p.conf.AcceptAddr != "" {
		networks = prepareNetworks(p.conf.AcceptAddr)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := p.llog.WithRequest(r)
		// network verification
		if networks != nil && !acceptAddress(networks, r.RemoteAddr) {
			l.Info("Proxy: request forbidden by network restrictions")
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		// no user verification
		if len(p.conf.Users) == 0 {
			h.ServeHTTP(w, r)
			return
		}

		// get authenticated user
		usr, pass, _ := r.BasicAuth()
		if usr == "" && r.URL != nil && r.URL.User != nil {
			usr = r.URL.User.Username()
			pass, _ = r.URL.User.Password()
		}

		// check authenticated user
		if usr != "" {
			user := p.globals.GetUser(usr)
			if p.conf.AcceptUser(user.Login) && checkUser(user, pass, p.globals) {
				// user ok
				l.With("user", user.Login).Info("Proxy: request accepted for user")
				r.Header.Set("X-Authenticated-User", usr)
				h.ServeHTTP(w, r)
				return
			}
		}

		// user need authentication
		w.Header().Set("WWW-Authenticate", "Basic realm=\"SecProxy\"")
		l.With("status", 401).Info("Proxy: user unauthorized; need login")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	})
}

func (p *proxyEndpoint) metricsMW(h http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		writer := &common.ResponseWriter{ResponseWriter: w, Status: 200}

		defer func() {
			// prometheus statistics
			elapsed := float64(time.Since(now)) / float64(time.Second)
			method := strings.ToLower(r.Method)
			code := strconv.Itoa(writer.Status)
			group := groupStatusCode(writer.Status)
			port := r.URL.Port()
			metricReqCnt.WithLabelValues(method, code, group, p.conf.Name, port).Inc()
			metricReqDur.WithLabelValues(method, code, group, p.conf.Name, port).Observe(elapsed)

			// internal statistics
			switch {
			case writer.Status == 401:
				atomic.AddUint32(&p.status401, 1)
			case writer.Status == 403:
				atomic.AddUint32(&p.status403, 1)
			case writer.Status >= 400:
				atomic.AddUint32(&p.statusFail, 1)
			case writer.Status < 400:
				atomic.AddUint32(&p.statusOk, 1)
			}
		}()

		h.ServeHTTP(writer, r)
	})
}

func groupStatusCode(code int) string {
	switch {
	case code >= 100 && code < 200:
		return "1xx"
	case code < 300:
		return "2xx"
	case code < 400:
		return "3xx"
	case code < 500:
		return "4xx"
	case code < 600:
		return "5xx"
	}
	return "unk"
}

func loadClientCerts(certs []string) (c []tls.Certificate, err error) {
	for _, certName := range certs {
		certPEM, err := ioutil.ReadFile(certName)
		if err != nil {
			return nil, fmt.Errorf("load cert %s error: %s", certName, err)
		}

		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return nil, fmt.Errorf("decode cert %s error", certName)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse cert %s error: %s", certName, err)
		}

		c = append(c, tls.Certificate{Leaf: cert})
	}
	return
}

func prepareNetworks(addrs string) (networks []*net.IPNet) {
	for _, n := range strings.Fields(addrs) {
		n = strings.TrimSpace(n)
		if strings.Contains(n, "/") {
			if _, network, err := net.ParseCIDR(n); err == nil {
				networks = append(networks, network)
			} else {
				logServer.With("err", err).With("net", n).
					Warn("Proxy: prepare networks error")
			}
		} else {
			if ip := net.ParseIP(n); ip != nil {
				var mask net.IPMask
				if len(ip) == 4 { // ipv4
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
				network := &net.IPNet{IP: ip, Mask: mask}
				networks = append(networks, network)
			} else {
				logServer.With("net", n).Warn("Proxy: prepare ip error")
			}
		}
	}

	logServer.With("networks", networks).With("inp", addrs).
		Debug("Proxy: prepareNetworks done")
	return
}

func acceptAddress(networks []*net.IPNet, addr string) bool {
	// cut off port
	portPos := strings.LastIndex(addr, ":")
	if portPos > -1 {
		addr = addr[:portPos]
	}

	a := net.ParseIP(addr)
	if a == nil {
		logServer.With("addr", addr).Warn("Proxy: acceptAddress parse error")
		return false
	}

	for _, n := range networks {
		if n.Contains(a) {
			return true
		}
	}
	return false
}
