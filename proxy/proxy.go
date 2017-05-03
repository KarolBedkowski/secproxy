package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"io/ioutil"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"log"
	"net"
	"strings"
	"sync"
)

type proxyEndpoints struct {
	endpoints map[string]*proxyEndpoint
	mu        sync.RWMutex
}

func newProxyEndpoints() *proxyEndpoints {
	return &proxyEndpoints{
		endpoints: make(map[string]*proxyEndpoint),
	}
}

var (
	endpoints   = newProxyEndpoints()
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
	logServer.Info("Proxy: starting %s", name)
	conf := globals.GetEndpoint(name)
	if conf == nil {
		return fmt.Errorf("invalid endpoint")
	}

	endpoints.mu.Lock()
	e, ok := endpoints.endpoints[name]
	if ok {
		e.Update(*conf)
	} else {
		e = newProxyEndpoint(*conf, globals)
		endpoints.endpoints[name] = e
	}

	endpoints.mu.Unlock()

	if statusHTTP, statusHTTPS := e.status(); !statusHTTPS.canStart() || !statusHTTP.canStart() {
		return fmt.Errorf("already running")
	}

	return e.Start()
}

func StopEndpoint(name string) {
	endpoints.mu.Lock()
	defer endpoints.mu.Unlock()

	e, ok := endpoints.endpoints[name]
	if ok {
		e.Stop()
	}
}

func EndpointRunning(name string) (string, string, bool) {
	endpoints.mu.Lock()
	defer endpoints.mu.Unlock()

	e, ok := endpoints.endpoints[name]
	if ok {
		statusHTTP, statusHTTPS := e.status()
		return statusHTTP.String(), statusHTTPS.String(), statusHTTP == EndpointStarted || statusHTTPS == EndpointStarted
	}
	return EndpointStopped.String(), EndpointStopped.String(), true
}

func EndpointErrors(name string) (string, string) {
	endpoints.mu.Lock()
	defer endpoints.mu.Unlock()

	e, ok := endpoints.endpoints[name]
	if ok {
		return e.error()
	}
	return "", ""
}

func EndpointsInfo() []*EndpointInfo {
	endpoints.mu.Lock()
	defer endpoints.mu.Unlock()

	var stats []*EndpointInfo
	for _, e := range endpoints.endpoints {
		stats = append(stats, e.Info())
	}

	return stats
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
