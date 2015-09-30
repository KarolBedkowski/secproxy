package logging

import (
	"flag"
	log "gopkg.in/inconshreveable/log15.v2"
	"net/http"
	"os"
)

var (
	Log         = log.New()
	logFilename = *flag.String("log", "./secproxy.log", "Log file name")
	debug       = *flag.Int("debug", 0, "Run in normal mode (0), debug mode (1) or verbose mode (2)")
)

func Init() {
	filehandler := log.Must.FileHandler(logFilename, log.LogfmtFormat())
	handler := log.MultiHandler(
		filehandler,
		log.StreamHandler(os.Stderr, log.TerminalFormat()))
	if debug > 1 {
		handler = log.CallerStackHandler("%+v", handler)
	} else {
		handler = log.CallerFileHandler(handler)
	}
	if debug < 1 {
		handler = log.LvlFilterHandler(log.LvlInfo, handler)
	}
	log.Root().SetHandler(handler)
}

func LogFilename() string {
	return logFilename
}

func DebugLevel() int {
	return debug
}

func Debug(msg string, args ...interface{}) {
	Log.Debug(msg, args...)
}

func Info(msg string, args ...interface{}) {
	Log.Info(msg, args...)
}

func Warn(msg string, args ...interface{}) {
	Log.Warn(msg, args...)
}

func Error(msg string, args ...interface{}) {
	Log.Error(msg, args...)
}

func Panic(msg string, args ...interface{}) {
	Log.Crit(msg, args...)
}

func LogForRequest(l log.Logger, r *http.Request) log.Logger {
	ctx := log.Ctx{
		"method":     r.Method,
		"host":       r.Host,
		"url":        r.URL,
		"requesturi": r.RequestURI,
		"remote":     r.RemoteAddr,
		"proto":      r.Proto,
		//		"header":     r.Header,
	}
	if val, ok := r.Header["X-Forwarded-For"]; ok {
		ctx["x_forward_for"] = val
	}
	if val, ok := r.Header["X-Authenticated-User"]; ok {
		ctx["x_authenticate_user"] = val
	}
	return l.New(ctx)
}

func NewLogger(module string) log.Logger {
	return Log.New("module", module)
}
