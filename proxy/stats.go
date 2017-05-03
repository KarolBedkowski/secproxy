//
// stats.go
// Copyright (C) 2017 Karol Będkowski
//

package proxy

import "sync"

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

type endpointState struct {
	statusHTTP  EndpointStatus
	statusHTTPS EndpointStatus
	errorHTTP   string
	errorHTTPS  string

	serverHTTPClose  chan bool
	serverHTTPSClose chan bool

	fail      uint
	success   uint
	status401 uint
	status403 uint
}

func newState() *endpointState {
	return &endpointState{
		statusHTTP:  EndpointNotConfigured,
		statusHTTPS: EndpointNotConfigured,

		serverHTTPClose:  make(chan bool),
		serverHTTPSClose: make(chan bool),
	}
}

type endpointsInfo struct {
	mutex  sync.RWMutex
	states map[string]*endpointState
}

func newEndpointsInfo() *endpointsInfo {
	return &endpointsInfo{
		states: make(map[string]*endpointState),
	}
}

func (e *endpointsInfo) addEndpoint(endpoint string) *endpointState {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	es, ok := e.states[endpoint]
	if ok {
		return es
	}
	es = newState()
	e.states[endpoint] = es
	return es
}

func (e *endpointsInfo) getState(endpoint string) (*endpointState, bool) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	st, ok := e.states[endpoint]
	return st, ok
}

func (e *endpointsInfo) setStatusHTTP(endpoint string, status EndpointStatus, err string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	es, ok := e.states[endpoint]
	if ok {
		es.statusHTTP = status
		es.errorHTTP = err
	}
}

func (e *endpointsInfo) setStatusHTTPS(endpoint string, status EndpointStatus, err string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	es, ok := e.states[endpoint]
	if ok {
		es.statusHTTPS = status
		es.errorHTTPS = err
	}
}

func (e *endpointsInfo) addSuccess(endpoint string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if es, ok := e.states[endpoint]; ok {
		es.success += 1
	}
}

func (e *endpointsInfo) addFailed(endpoint string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if es, ok := e.states[endpoint]; ok {
		es.fail += 1
	}
}

func (e *endpointsInfo) addStatus401(endpoint string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if es, ok := e.states[endpoint]; ok {
		es.status401 += 1
	}
}

func (e *endpointsInfo) addStatus403(endpoint string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if es, ok := e.states[endpoint]; ok {
		es.status403 += 1
	}
}

func (e *endpointsInfo) status(endpoint string) (EndpointStatus, EndpointStatus) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if es, ok := e.states[endpoint]; ok {
		return es.statusHTTP, es.statusHTTPS
	}
	return EndpointNotExits, EndpointNotExits
}

func (e *endpointsInfo) error(endpoint string) (string, string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if es, ok := e.states[endpoint]; ok {
		return es.errorHTTP, es.errorHTTPS
	}
	return "", ""
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

func (e *endpointsInfo) GetInfo() []*EndpointInfo {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	var stats []*EndpointInfo
	for name, st := range e.states {
		ei := &EndpointInfo{
			Endpoint:    name,
			Fail:        st.fail,
			Success:     st.success,
			Status401:   st.status401,
			Status403:   st.status403,
			Total:       st.fail + st.success + st.status401 + st.status403,
			StatusHTTP:  st.statusHTTP.String(),
			StatusHTTPS: st.statusHTTPS.String(),
			ErrorHTTP:   st.errorHTTP,
			ErrorHTTPS:  st.errorHTTPS,
		}
		stats = append(stats, ei)
	}

	return stats
}
