package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"io/ioutil"
	"k.prv/secproxy/common"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	endpoints   = newEndpointsInfo()
	logServer   = logging.NewLogger("server")
	proxyLogger = log.New(logServer.Writer(), "proxy", 0)

	metricsLabels = []string{"method", "code", "code_group", "endpoint", "port"}

	metricsOpts = prometheus.SummaryOpts{
		Subsystem: "proxy",
		Namespace: "secproxy",
	}

	metricReqCnt = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   metricsOpts.Namespace,
			Subsystem:   metricsOpts.Subsystem,
			Name:        "requests_total",
			Help:        "Total number of HTTP requests made per url.",
			ConstLabels: metricsOpts.ConstLabels,
		},
		metricsLabels,
	)

	metricReqDur = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Namespace:   metricsOpts.Namespace,
			Subsystem:   metricsOpts.Subsystem,
			Name:        "request_duration_seconds",
			Help:        "The HTTP request latencies in seconds.",
			ConstLabels: metricsOpts.ConstLabels,
		},
		metricsLabels,
	)
)

func init() {
	prometheus.MustRegister(metricReqCnt)
	prometheus.MustRegister(metricReqDur)
}

func StartEndpoint(name string, globals *config.Globals) error {
	llog := logServer.With("endpoint", name)
	llog.Info("Proxy: starting endpoint")

	conf := globals.GetEndpoint(name)
	if conf == nil {
		return fmt.Errorf("invalid endpoint")
	}

	if statusHTTP, statusHTTPS := endpoints.status(name); !statusHTTPS.canStart() || !statusHTTP.canStart() {
		llog.Info("Proxy: endpoint can't start; statuses: %s, %s", statusHTTP, statusHTTPS)
		return fmt.Errorf("already running")
	}

	pe := &proxyEndpoint{
		conf:    conf,
		globals: globals,
		name:    name,
		llog:    llog,
		st:      endpoints.addEndpoint(name),
	}

	handler, err := pe.createHandler()
	if err != nil {
		return err
	}

	var errHTTP, errHTTPS error
	if conf.HTTPAddress != "" {
		if errHTTP = pe.startEndpointHTTP(handler); errHTTP != nil {
			llog.With("err", errHTTP).Info("Proxy: start HTTP server error")
			endpoints.setStatusHTTP(name, EndpointError, errHTTP.Error())
		}
	} else {
		endpoints.setStatusHTTP(name, EndpointStopped, "")
	}

	if conf.HTTPSAddress != "" {
		if errHTTPS = pe.startEndpointHTTPS(handler); errHTTPS != nil {
			llog.With("err", errHTTPS).Info("Proxy: start HTTPS server error")
			endpoints.setStatusHTTPS(name, EndpointError, errHTTPS.Error())
		}
	} else {
		endpoints.setStatusHTTPS(name, EndpointStopped, "")
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

type proxyEndpoint struct {
	conf    *config.EndpointConf
	globals *config.Globals
	name    string
	llog    logging.Logger
	st      *endpointState
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
	handler = authenticationMW(handler, p.name, p.globals)
	handler = common.LogHandler(handler, "server:", map[string]interface{}{"endpoint": p.name, "module": "server"})
	// TODO: stats handler
	handler = metricsMW(handler, p.name, p.globals)
	return handler, nil
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
			stopChain := p.st.serverHTTPClose
			go s.Serve(ls)
			endpoints.setStatusHTTP(p.name, EndpointStarted, "")
			select {
			case <-stopChain:
				ls.Close()
				p.llog.Info("Proxy: stopping HTTP on %v", s.Addr)
				endpoints.setStatusHTTP(p.name, EndpointStopped, "")
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
		endpoints.setStatusHTTPS(p.name, EndpointError, err.Error())
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
			stopChain := p.st.serverHTTPSClose
			go s.Serve(tlsListener)
			endpoints.setStatusHTTPS(p.name, EndpointStarted, "")
			select {
			case <-stopChain:
				ln.Close()
				p.llog.Info("Proxy: stopping HTTPS on %v", s.Addr)
				endpoints.setStatusHTTPS(p.name, EndpointStopped, "")
				return
			}
		}()
	}
	return nil
}

func StopEndpoint(name string) {
	llog := logServer.With("endpoint", name)
	llog.Info("Proxy: stop endpoint")

	statusHTTP, statusHTTPS := endpoints.status(name)
	if statusHTTP == EndpointStarted {
		llog.Debug("Proxy: stopping http")
		if state, ok := endpoints.getState(name); ok {
			state.serverHTTPClose <- true
		}
	}
	if statusHTTPS == EndpointStarted {
		llog.Debug("Proxy: stopping https")
		if state, ok := endpoints.getState(name); ok {
			state.serverHTTPSClose <- true
		}
	}
}

func EndpointRunning(name string) (string, string, bool) {
	statusHTTP, statusHTTPS := endpoints.status(name)
	return statusHTTP.String(), statusHTTPS.String(), statusHTTP == EndpointStarted || statusHTTPS == EndpointStarted
}

func EndpointErrors(name string) (string, string) {
	return endpoints.error(name)
}

func EndpointsInfo() []*EndpointInfo {
	return endpoints.GetInfo()
}

func prepareNetworks(addrs string) (networks []*net.IPNet) {
	for _, n := range strings.Fields(addrs) {
		n = strings.TrimSpace(n)
		if strings.Contains(n, "/") {
			if _, network, err := net.ParseCIDR(n); err == nil {
				networks = append(networks, network)
			} else {
				logServer.With("err", err).
					With("net", n).
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
				network := &net.IPNet{ip, mask}
				networks = append(networks, network)
			} else {
				logServer.With("net", n).
					Warn("Proxy: prepare ip error")
			}
		}
	}
	logServer.With("networks", networks).
		With("inp", addrs).
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

func authenticationMW(h http.Handler, endpoint string, globals *config.Globals) http.Handler {
	conf := globals.GetEndpoint(endpoint)
	var networks []*net.IPNet
	if conf.AcceptAddr != "" {
		networks = prepareNetworks(conf.AcceptAddr)
	}

	llog := logServer.With("endpoint", endpoint)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := llog.WithRequest(r)
		if networks != nil {
			if !acceptAddress(networks, r.RemoteAddr) {
				l.Info("Proxy: authenticationMW 403 Forbidden - addr")
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				endpoints.addStatus403(endpoint)
				return
			}
		}

		if len(conf.Users) == 0 {
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
			endpoints.addStatus401(endpoint)
			return
		}

		user := globals.GetUser(usr)
		if user.Active && conf.AcceptUser(user.Login) && user.CheckPassword(pass) {
			l.With("user", user.Login).Debug("User authenticated")
			r.Header.Set("X-Authenticated-User", usr)
			endpoints.addSuccess(endpoint)
			h.ServeHTTP(w, r)
			return
		}
		//log.Info("authenticationMW ", endpoint, " 403 Forbidden")
		//http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		endpoints.addStatus401(endpoint)

		w.Header().Set("WWW-Authenticate", "Basic realm=\"REALM\"")
		l.With("user", user.Login).With("user_active", user.Active).
			With("status", 401).
			Info("Proxy: authenticationMW 401 Unauthorized")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
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

func metricsMW(h http.Handler, endpoint string, globals *config.Globals) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()

		writer := &common.ResponseWriter{ResponseWriter: w, Status: 200}

		defer func() {
			elapsed := float64(time.Since(now)) / float64(time.Second)
			method := strings.ToLower(r.Method)
			code := strconv.Itoa(writer.Status)
			group := groupStatusCode(writer.Status)
			port := r.URL.Port()
			metricReqCnt.WithLabelValues(method, code, group, endpoint, port).Inc()
			metricReqDur.WithLabelValues(method, code, group, endpoint, port).Observe(elapsed)
		}()

		h.ServeHTTP(writer, r)
	})
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
