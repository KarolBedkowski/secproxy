package logging

import (
	"flag"
	"fmt"
	"github.com/Sirupsen/logrus"
	"net/http"
	"os"
	"runtime"
	"strings"
)

var (
	Log         = logrus.New()
	logFilename string
)

// Based on prometheus_common/log

type levelFlag string

// String implements flag.Value.
func (f levelFlag) String() string {
	return fmt.Sprintf("%q", string(f))
}

// Set implements flag.Value.
func (f levelFlag) Set(level string) error {
	l, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}
	Log.Level = l
	return nil
}

type logfileFlag string

func (l logfileFlag) String() string {
	return logFilename
}

// Set implements flag.Value.
func (f logfileFlag) Set(name string) error {
	file, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		logFilename = ""
		return fmt.Errorf("open file for logging error: %s", err)
	}
	Log.Out = file
	logFilename = name
	return nil
}

func init() {
	flag.CommandLine.Var(
		levelFlag(Log.Level.String()),
		"log.level",
		"Only log messages with the given severity or above. Valid levels: [debug, info, warn, error, fatal]",
	)
	flag.CommandLine.Var(
		logfileFlag(logFilename),
		"log.file",
		"Log file name; when empty log to stdout",
	)
}

func Init() {
}

func SetLogLevel(level string) (ok bool) {
	l, err := logrus.ParseLevel(level)
	if err != nil {
		return false
	}
	Log.Level = l
	return true
}

func LogFilename() string {
	return logFilename
}

type Logger interface {
	Debug(string, ...interface{})
	Info(string, ...interface{})
	Warn(string, ...interface{})
	Error(string, ...interface{})
	Panic(string, ...interface{})
	With(key string, value interface{}) Logger
	WithRequest(r *http.Request) Logger
}

type logger struct {
	entry *logrus.Entry
}

func NewLogger(module string) Logger {
	l := Log.WithField("module", module)
	return logger{entry: l}
}

func (l *logger) sourcedlog() *logrus.Entry {
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		file = "<???>"
		line = 1
	} else {
		slash := strings.LastIndex(file, "/")
		file = file[slash+1:]
	}
	return l.entry.WithField("source", fmt.Sprintf("%s:%d", file, line))
}

func (l logger) Debug(msg string, args ...interface{}) {
	l.sourcedlog().Debugf(msg, args...)
}

func (l logger) Info(msg string, args ...interface{}) {
	l.sourcedlog().Infof(msg, args...)
}

func (l logger) Warn(msg string, args ...interface{}) {
	l.sourcedlog().Warnf(msg, args...)
}

func (l logger) Error(msg string, args ...interface{}) {
	l.sourcedlog().Errorf(msg, args...)
}

func (l logger) Panic(msg string, args ...interface{}) {
	l.sourcedlog().Panicf(msg, args...)
}

func (l logger) With(key string, value interface{}) Logger {
	return logger{l.entry.WithField(key, value)}
}

func (l logger) WithRequest(r *http.Request) Logger {
	return logger{LogForRequest(l.entry, r)}
}

func sourcedlog(l *logrus.Logger) *logrus.Entry {
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		file = "<???>"
		line = 1
	} else {
		slash := strings.LastIndex(file, "/")
		file = file[slash+1:]
	}
	return l.WithField("source", fmt.Sprintf("%s:%d", file, line))
}

func Debug(msg string, args ...interface{}) {
	sourcedlog(Log).Debugf(msg, args...)
}

func Info(msg string, args ...interface{}) {
	sourcedlog(Log).Infof(msg, args...)
}

func Warn(msg string, args ...interface{}) {
	sourcedlog(Log).Warnf(msg, args...)
}

func Error(msg string, args ...interface{}) {
	sourcedlog(Log).Errorf(msg, args...)
}

func Panic(msg string, args ...interface{}) {
	sourcedlog(Log).Panicf(msg, args...)
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
