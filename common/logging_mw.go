package common

import (
	"k.prv/secproxy/logging"
	"net/http"
	"runtime/debug"
	"time"
)

// LogHandler log all requests.
func LogHandler(h http.Handler, prefix string, logkv map[string]interface{}) http.HandlerFunc {
	l := logging.NewLogger("common.logging_mw")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		log := l.WithRequest(r).With("start", start.Unix()).WithFields(logkv)
		log.Debug(prefix + " begin request")

		writer := &ResponseWriter{ResponseWriter: w, Status: 200}

		defer func() {
			end := time.Now()
			stack := debug.Stack()
			if err := recover(); err == nil {
				log.With("status", writer.Status).
					With("end", end.Unix()).
					With("time", end.Sub(start).String()).
					Debug(prefix + " request finished")
			} else {
				log.With("status", writer.Status).
					With("err", err).
					With("end", end.Unix()).
					With("duration", end.Sub(start).String()).
					With("stack", string(stack)).
					Info(prefix + " request error")
			}
		}()

		h.ServeHTTP(writer, r)
	})
}

func RequestLogEntry(r *http.Request) string {
	return r.Method + " " + r.URL.String() + " " + r.RemoteAddr
}
