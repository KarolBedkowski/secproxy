package logging

import (
	"flag"
	"fmt"
	"github.com/Sirupsen/logrus"
	"net/http"
	"os"
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
