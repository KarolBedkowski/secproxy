package proxy

import (
	"fmt"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"log"
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
)

// StartEndpoint by name
func StartEndpoint(name string, globals *config.Globals) error {
	logServer.Info("Proxy: starting %s", name)
	conf := globals.GetEndpoint(name)
	if conf == nil {
		return fmt.Errorf("invalid endpoint")
	}

	endpoints.mu.Lock()
	e, ok := endpoints.endpoints[name]
	if ok {
		e.update(conf)
	} else {
		e = newProxyEndpoint(conf, globals)
		endpoints.endpoints[name] = e
	}

	endpoints.mu.Unlock()

	if statusHTTP, statusHTTPS := e.status(); !statusHTTPS.canStart() || !statusHTTP.canStart() {
		return fmt.Errorf("already running")
	}

	return e.start()
}

// StopEndpoint by name
func StopEndpoint(name string) error {
	endpoints.mu.Lock()
	defer endpoints.mu.Unlock()

	e, ok := endpoints.endpoints[name]
	if ok {
		return e.stop()
	}
	return fmt.Errorf("unknown endpoint %v", name)
}

// EndpointState return http, https status and "is running" flag
func EndpointState(name string) (string, string, bool) {
	endpoints.mu.Lock()
	defer endpoints.mu.Unlock()

	e, ok := endpoints.endpoints[name]
	if ok {
		statusHTTP, statusHTTPS := e.status()
		return statusHTTP.String(), statusHTTPS.String(), statusHTTP == EndpointStarted || statusHTTPS == EndpointStarted
	}
	return EndpointStopped.String(), EndpointStopped.String(), false
}

// EndpointErrors check endpoint (by name) for errors
func EndpointErrors(name string) (string, string) {
	endpoints.mu.Lock()
	defer endpoints.mu.Unlock()

	e, ok := endpoints.endpoints[name]
	if ok {
		return e.error()
	}
	return "", ""
}

// EndpointsInfo generate information about all endpoints
func EndpointsInfo() []*EndpointInfo {
	endpoints.mu.Lock()
	defer endpoints.mu.Unlock()

	var stats []*EndpointInfo
	for _, e := range endpoints.endpoints {
		stats = append(stats, e.info())
	}

	return stats
}
