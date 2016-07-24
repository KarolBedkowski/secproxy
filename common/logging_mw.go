package common

import (
	l "k.prv/secproxy/logging"
	"net/http"
	"runtime/debug"
	"time"
)

// LogHandler log all requests.
func LogHandler(h http.Handler, prefix string, logkv ...interface{}) http.HandlerFunc {
	orgLogkv := logkv
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logkv = append(orgLogkv, "start")
		logkv = append(logkv, start.Unix())
		logger := l.LogForRequest(l.Log, r).New(logkv...)
		logger.Debug(prefix + "begin request")

		writer := &ResponseWriter{ResponseWriter: w, Status: 200}

		defer func() {
			end := time.Now()
			stack := debug.Stack()
			if err := recover(); err == nil {
				logger.Debug(prefix+"request finished", "status", writer.Status, "end", end.Unix(), "time", end.Sub(start).String())
			} else {
				logger.Debug(prefix+"request error", "status", writer.Status, "err", err, "end", end.Unix(), "time", end.Sub(start).String(), "st", string(stack))
			}
		}()

		h.ServeHTTP(writer, r)
	})
}

func RequestLogEntry(r *http.Request) string {
	return r.Method + " " + r.URL.String() + " " + r.RemoteAddr
}
