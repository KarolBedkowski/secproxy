package logging

import (
	log "gopkg.in/inconshreveable/log15.v2"
	"net/http"
	"os"
)

var (
	Log         = log.New()
	logFilename string
	debug       = 0
)

func Init(logFileName string, debug int) {
	setSettings(debug, logFileName)
}

func setSettings(level int, filename string) {
	logFilename = filename
	debug = level

	filehandler := log.Must.FileHandler(filename, log.LogfmtFormat())
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
	log.Info("Logging started", "level", debug, "log_file", logFilename)
}

func LogFilename() string {
	return logFilename
}

func DebugLevel() int {
	return debug
}

func SetDebugLevel(level int) (ok bool) {
	if level != debug {
		setSettings(level, logFilename)
		ok = true
	}
	return
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
