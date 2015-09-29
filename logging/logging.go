package logging

import (
	log "gopkg.in/inconshreveable/log15.v2"
	"net/http"
	"os"
)

var (
	Log = log.New()
)

func Init(logFilename string, debug int) {
	filehandler := log.Must.FileHandler(logFilename, log.LogfmtFormat())
	handler := log.MultiHandler(
		filehandler,
		log.StreamHandler(os.Stderr, log.TerminalFormat()))
	if debug > 1 {
		handler = log.CallerStackHandler("%+v", handler)
	} else {
		handler = log.CallerFileHandler(handler)
	}
	if debug == 0 {
		handler = log.LvlFilterHandler(log.LvlInfo, handler)
	}
	log.Root().SetHandler(handler)
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
	return l.New("method", r.Method, "url", r.URL, "remote", r.RemoteAddr)
}

func NewLogger(module string) log.Logger {
	return Log.New("module", module)
}
