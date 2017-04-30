package logging

import (
	"github.com/Sirupsen/logrus"
	"net/http"
)

var (
	Log         = logrus.New()
	logFilename string
	logLevel    = 0
)

func Init(logFileName string, debug int) {
	setSettings(debug, logFileName)
}

func setSettings(level int, filename string) {
	logLevel = level
	if level > 0 {
		Log.Level = logrus.DebugLevel
	} else {
		Log.Level = logrus.InfoLevel
	}

	logFilename = filename
}

func LogFilename() string {
	return logFilename
}

func DebugLevel() int {
	return logLevel
}

func SetDebugLevel(level int) (ok bool) {
	if level != logLevel {
		setSettings(level, logFilename)
		ok = true
	}
	return
}

func Debug(msg string, args ...interface{}) {
	Log.Debugf(msg, args...)
}

func Info(msg string, args ...interface{}) {
	Log.Infof(msg, args...)
}

func Warn(msg string, args ...interface{}) {
	Log.Warnf(msg, args...)
}

func Error(msg string, args ...interface{}) {
	Log.Errorf(msg, args...)
}

func Panic(msg string, args ...interface{}) {
	Log.Panicf(msg, args...)
}

func LogForRequest(l interface{}, r *http.Request) *logrus.Entry {
	var le *logrus.Entry
	le, ok := l.(*logrus.Entry)
	if !ok {
		le = logrus.NewEntry(l.(*logrus.Logger))
	}
	f := logrus.Fields{
		"method":     r.Method,
		"host":       r.Host,
		"url":        r.URL,
		"requesturi": r.RequestURI,
		"remote":     r.RemoteAddr,
		"proto":      r.Proto,
		//		"header":     r.Header,
	}
	if val, ok := r.Header["X-Forwarded-For"]; ok {
		f["x_forward_for"] = val
	}
	if val, ok := r.Header["X-Authenticated-User"]; ok {
		f["x_authenticate_user"] = val
	}

	return le.WithFields(f)
}

func NewLogger(module string) *logrus.Entry {
	return Log.WithField("module", module)
}
