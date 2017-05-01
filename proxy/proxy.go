package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"expvar"
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
	"sync"
	"time"
)

type (
	state struct {
		running        bool
		runningSSL     bool
		serverClose    chan bool
		serverSSLClose chan bool
	}

	varState string
)

func (v varState) String() string {
	return string(v)
}

var (
	states   = make(map[string]*state)
	counters = expvar.NewMap("counters")
	servStat = expvar.NewMap("states")
	errors   = expvar.NewMap("errors")
	mu       sync.RWMutex

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

func StartEndpoint(name string, globals *config.Globals) (errstr []string) {
	llog := logServer.With("endpoint", name)
	llog.Info("Proxy: starting endpoint")

	mu.Lock()
	defer mu.Unlock()

	var st *state
	var ok bool
	if st, ok = states[name]; ok && st != nil {
		if st.running || st.runningSSL {
			llog.Info("Proxy: endpoint already started")
			return []string{"already running"}
		}
	}
	if st == nil {
		st = &state{
			serverClose:    make(chan bool),
			serverSSLClose: make(chan bool),
		}
		states[name] = st
	}

	servStat.Set(name, varState("stopped"))
	servStat.Set(name+"|ssl", varState("stopped"))
	conf := globals.GetEndpoint(name)
	if conf == nil {
		return []string{"invalid endpoint"}
	}
	uri, err := url.Parse(conf.Destination)
	if err != nil {
		return []string{"invalid url"}
	}

	var handler http.Handler

	revproxy := httputil.NewSingleHostReverseProxy(uri)
	revproxy.ErrorLog = proxyLogger
	handler = http.Handler(revproxy)
	handler = authenticationMW(handler, name, globals)
	handler = counterMw(handler, name)
	handler = common.LogHandler(handler, "server:", map[string]interface{}{"endpoint": name, "module": "server"})
	// TODO: stats handler
	handler = metricsMW(handler, name, globals)

	if conf.HTTPAddress != "" {
		llog.Info("Proxy: starting HTTP on %v", conf.HTTPAddress)
		s := &http.Server{
			Addr:         conf.HTTPAddress,
			Handler:      handler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		ls, e := net.Listen("tcp", conf.HTTPAddress)
		if e != nil {
			llog.With("err", e).
				Info("Proxy: start HTTP server error")
			errstr = append(errstr, "starting http error "+e.Error())
			errors.Set(name, varState(e.Error()))
		} else {
			go func() {
				st.running = true
				go s.Serve(ls)
				servStat.Set(name, varState("running"))
				errors.Set(name, varState(""))
				select {
				case <-st.serverClose:
					llog.Info("Proxy: stopping http")
					ls.Close()
					st.running = false
					servStat.Set(name, varState("stopped"))
					return
				}
			}()
		}
	}

	if conf.HTTPSAddress != "" {
		llog.Info("Proxy: starting HTTPS on %s", conf.HTTPSAddress)
		s := &http.Server{
			Addr:         conf.HTTPSAddress,
			Handler:      handler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		tlsConfig := &tls.Config{
			RootCAs:                  globals.TLSRootsCAs,
			ClientCAs:                globals.TLSRootsCAs,
			PreferServerCipherSuites: true,
		}
		if tlsConfig.NextProtos == nil {
			tlsConfig.NextProtos = []string{"http/1.1"}
		}

		if cert, err := tls.LoadX509KeyPair(conf.SslCert, conf.SslKey); err != nil {
			llog.With("err", err).Info("Proxy: starting HTTPS cert error")
			errstr = append(errstr, "starting https - cert error "+err.Error())
			errors.Set(name+"|ssl", varState(err.Error()))
		} else {
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		}

		if len(conf.ClientCertificates) > 0 {
			for _, certName := range conf.ClientCertificates {
				clog := llog.With("certname", certName)
				certPEM, err := ioutil.ReadFile(certName)
				if err != nil {
					clog.With("err", err).Info("Proxy: load cert error")
					continue
				}
				block, _ := pem.Decode([]byte(certPEM))
				if block == nil {
					clog.Info("Proxy: decode cert error")
					continue
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					clog.With("err", err).Info("Proxy: decode cert error")
					continue
				}
				tlsConfig.Certificates = append(tlsConfig.Certificates, tls.Certificate{Leaf: cert})
				clog.Debug("loaded cert: cn=%s ", cert.Subject.CommonName)
			}
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				for _, cg := range verifiedChains {
					for _, cert := range cg {
						for _, ccert := range tlsConfig.Certificates {
							c := ccert.Leaf
							if c != nil && cert.Equal(c) {
								llog.Debug("Proxy: found cert cn=%s", cert.Subject.CommonName)
								return nil
							}
						}
					}
				}
				return fmt.Errorf("unknown client certificate")
			}
		}

		if ln, err := net.Listen("tcp", conf.HTTPSAddress); err != nil {
			llog.With("err", err).
				Error("Proxy: start HTTPS listen error")
			errstr = append(errstr, "starting https error "+err.Error())
			errors.Set(name+"|ssl", varState(err.Error()))
		} else {
			tlsListener := tls.NewListener(ln, tlsConfig)
			go func() {
				st.runningSSL = true
				go s.Serve(tlsListener)
				servStat.Set(name+"|ssl", varState("running"))
				errors.Set(name+"|ssl", varState(""))
				select {
				case <-st.serverSSLClose:
					llog.Info("Proxy: stopping HTTPS")
					ln.Close()
					st.runningSSL = false
					servStat.Set(name, varState("stopped"))
					return
				}
			}()
		}
	}

	return
}

func StopEndpoint(name string) {
	llog := logServer.With("endpoint", name)
	llog.Info("Proxy: stop endpoint")
	mu.RLock()
	defer mu.RUnlock()
	state, ok := states[name]
	if !ok {
		return
	}
	if state.running {
		llog.Debug("Proxy: stopping http")
		state.serverClose <- true
	}
	if state.runningSSL {
		llog.Debug("Proxy: stopping https")
		state.serverSSLClose <- true
	}
}

func EndpointRunning(name string) bool {
	mu.RLock()
	defer mu.RUnlock()
	if st, ok := states[name]; ok {
		return st.running || st.runningSSL
	}
	return false
}

func EndpointErrors(name string) (e string) {
	if err := errors.Get(name); err != nil && err.String() != "" {
		logServer.With("endpoint", name).
			With("err", err).
			Debug("Proxt: get errors error")
		e = err.String() + "; "
	}
	if err := errors.Get(name + "|ssl"); err != nil && err.String() != "" {
		e = e + "SSL: " + err.String()
	}
	return e
}

func counterMw(h http.Handler, endpoint string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counters.Add(endpoint, 1)
		h.ServeHTTP(w, r)
	})
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
				counters.Add(endpoint+"|403", 1)
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
			counters.Add(endpoint+"|401", 1)
			return
		}

		user := globals.GetUser(usr)
		if user.Active && conf.AcceptUser(user.Login) && user.CheckPassword(pass) {
			l.With("user", user.Login).Debug("User authenticated")
			r.Header.Set("X-Authenticated-User", usr)
			counters.Add(endpoint+"|pass", 1)
			h.ServeHTTP(w, r)
			return
		}
		//log.Info("authenticationMW ", endpoint, " 403 Forbidden")
		//http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		counters.Add(endpoint+"|403", 1)

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
