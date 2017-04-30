package proxy

import (
	"crypto/tls"
	"expvar"
	"github.com/prometheus/client_golang/prometheus"
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

	log = logging.NewLogger("server")

	metricsLabels = []string{"method", "code", "code_group", "endpoint"}

	metricsOpts = prometheus.SummaryOpts{
		Subsystem: "http",
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
			Name:        "request_duration_microseconds",
			Help:        "The HTTP request latencies in microseconds.",
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
	log.Info("server.StartEndpoint starting ", "endpoint", name)

	mu.Lock()
	defer mu.Unlock()

	var st *state
	var ok bool
	if st, ok = states[name]; ok && st != nil {
		if st.running || st.runningSSL {
			log.Warn("server.StartEndpoint already started ", "enpoint", name)
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

	handler = httputil.NewSingleHostReverseProxy(uri)
	handler = authenticationMW(handler, name, globals)
	handler = counterMw(handler, name)
	handler = common.LogHandler(handler, "server:", map[string]interface{}{"endpoint": name, "module": "server"})
	// TODO: stats handler
	handler = metricsMW(handler, name, globals)

	if conf.HTTPAddress != "" {
		log.Info("server.StartEndpoint starting http", "endpoint", name)
		s := &http.Server{
			Addr:         conf.HTTPAddress,
			Handler:      handler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		ls, e := net.Listen("tcp", conf.HTTPAddress)
		if e != nil {
			log.Error("server.StartEndpoint starting http listen error ", "endpoint", name, "err", e)
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
					log.Info("server.StartEndpoint stop http ", "endpoint", name)
					ls.Close()
					st.running = false
					servStat.Set(name, varState("stopped"))
					return
				}
			}()
		}
	}

	if conf.HTTPSAddress != "" {
		log.Info("server.StartEndpoint starting https ", "endpoint", name)
		s := &http.Server{
			Addr:         conf.HTTPSAddress,
			Handler:      handler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		config := &tls.Config{}
		if config.NextProtos == nil {
			config.NextProtos = []string{"http/1.1"}
		}

		var err error
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0], err = tls.LoadX509KeyPair(conf.SslCert, conf.SslKey)
		if err != nil {
			log.Error("server.StartEndpoint starting https cert error", "err", err, "endpoint", name)
			errstr = append(errstr, "starting https - cert error "+err.Error())
			errors.Set(name+"|ssl", varState(err.Error()))
		} else {
			ln, err := net.Listen("tcp", conf.HTTPSAddress)
			if err != nil {
				log.Error("server.StartEndpoint starting https listen error ", "err", err, "endpoint", name)
				errstr = append(errstr, "starting https error "+err.Error())
				errors.Set(name+"|ssl", varState(err.Error()))
			} else {
				tlsListener := tls.NewListener(ln, config)
				go func() {
					st.runningSSL = true
					go s.Serve(tlsListener)
					servStat.Set(name+"|ssl", varState("running"))
					errors.Set(name+"|ssl", varState(""))
					select {
					case <-st.serverSSLClose:
						log.Info("server.StartEndpoint stop https", "endpoint", name)
						ln.Close()
						st.runningSSL = false
						servStat.Set(name, varState("stopped"))
						return
					}
				}()
			}
		}
	}

	return
}

func StopEndpoint(name string) {
	log.Info("server.StopEndpoint", "endpoint", name)
	mu.RLock()
	defer mu.RUnlock()
	state, ok := states[name]
	if !ok {
		return
	}
	if state.running {
		log.Debug("server.StopEndpoint stopping http", "endpoint", name)
		state.serverClose <- true
	}
	if state.runningSSL {
		log.Debug("server.StopEndpoint stopping https ", "endpoint", name)
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
		log.Debug("server.EndpointErrors", "err", err)
		e = err.String() + "; "
	}
	if err := errors.Get(name + "|ssl"); err != nil {
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
				log.Warn("authenticationMW prepare networks error", "err", err, "net", n)
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
				log.Warn("authenticationMW prepare ip error", "net", n)
			}
		}
	}
	log.Debug("prepareNetworks", "networks", networks, "inp", addrs)
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
		log.Warn("acceptAddress parse error", "addr", addr)
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

	llog := log.With("endpoint", endpoint)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if networks != nil {
			if !acceptAddress(networks, r.RemoteAddr) {
				llog.WithRequest(r).Info("authenticationMW 403 Forbidden - addr")
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
			w.Header().Set("WWW-Authenticate", "Basic realm=\"REALM\"")
			llog.WithRequest(r).With("status", 401).Info("authenticationMW 401 Unauthorized")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			counters.Add(endpoint+"|401", 1)
			return
		}

		user := globals.GetUser(usr)
		if user.Active && conf.AcceptUser(user.Login) && user.CheckPassword(pass) {
			r.Header.Set("X-Authenticated-User", usr)
			counters.Add(endpoint+"|pass", 1)
			h.ServeHTTP(w, r)
			return
		}
		//log.Info("authenticationMW ", endpoint, " 403 Forbidden")
		//http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		counters.Add(endpoint+"|403", 1)

		w.Header().Set("WWW-Authenticate", "Basic realm=\"REALM\"")
		llog.WithRequest(r).
			With("user", user.Login).With("user_active", user.Active).
			With("status", 401).
			Info("authenticationMW 401 Unauthorized")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	})
}

func groupStatusCode(code int) string {
	if code <= 100 && code < 200 {
		return "1xx"
	}
	if code < 300 {
		return "2xx"
	}
	if code < 400 {
		return "3xx"
	}
	if code < 500 {
		return "4xx"
	}
	if code < 600 {
		return "5xx"
	}
	return "unk"
}

func metricsMW(h http.Handler, endpoint string, globals *config.Globals) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()

		writer := &common.ResponseWriter{ResponseWriter: w, Status: 200}

		defer func() {
			elapsed := float64(time.Since(now)) / float64(time.Microsecond)
			method := strings.ToLower(r.Method)
			code := strconv.Itoa(writer.Status)
			group := groupStatusCode(writer.Status)
			metricReqCnt.WithLabelValues(method, code, group, endpoint).Inc()
			metricReqDur.WithLabelValues(method, code, group, endpoint).Observe(elapsed)
		}()

		h.ServeHTTP(writer, r)
	})
}
