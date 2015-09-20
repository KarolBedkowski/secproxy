package common

import (
	l "k.prv/secproxy/logging"
	"net/http"
	"runtime/debug"
	"time"
)

// loggingResponseWriter response writer with status
type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader store status of request
func (writer *loggingResponseWriter) WriteHeader(status int) {
	writer.ResponseWriter.WriteHeader(status)
	writer.status = status
}

// LogHandler log all requests.
func LogHandler(h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		l.Debug("begin request ", r.Method, " ", r.URL, " ", r.RemoteAddr, " ", start.Unix())
		writer := &loggingResponseWriter{ResponseWriter: w, status: 200}
		defer func() {
			end := time.Now()
			stack := debug.Stack()
			if err := recover(); err == nil {
				//l.Debugf("%d %s %s %s %s", writer.status, r.Method, r.URL.String(), r.RemoteAddr, end.Sub(start))
				l.Debug("request finished ", writer.status, " ", r.Method, " ", r.URL, " ", r.RemoteAddr, " ", start.Unix(), " ", end.Sub(start).String())
			} else {
				l.Debug("request error ", writer.status, " ", err, " ", r.Method, " ", r.URL, " ", r.RemoteAddr, " ", start.Unix(), " ", end.Sub(start).String(),
					" ", string(stack))
			}
		}()
		h.ServeHTTP(writer, r)
	})
}

func RequestLogEntry(r *http.Request) string {
	return r.Method + " " + r.URL.String() + " " + r.RemoteAddr
}
