//
// file_hook.go
// Copyright (C) 2017 Karol Będkowski
//

package logging

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"os"
	"sync"
)

type logrusFileHook struct {
	filename  string
	formatter logrus.Formatter
	file      *os.File
	lock      sync.Mutex
}

func newFileHook(filename string) (*logrusFileHook, error) {
	l := &logrusFileHook{
		filename: filename,
	}
	l.SetFormatter(&logrus.TextFormatter{})

	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		logFilename = ""
		return nil, fmt.Errorf("open file for logging error: %s", err)
	}
	l.file = file

	return l, nil
}

func (h *logrusFileHook) Close() {
	if h.file != nil {
		h.file.Close()
	}
}

func (h *logrusFileHook) SetFormatter(formatter logrus.Formatter) {
	h.formatter = formatter

	switch formatter.(type) {
	case *logrus.TextFormatter:
		textFormatter := formatter.(*logrus.TextFormatter)
		textFormatter.DisableColors = true
	}
}

func (h *logrusFileHook) Fire(entry *logrus.Entry) error {
	msg, err := h.formatter.Format(entry)

	h.lock.Lock()
	defer h.lock.Unlock()

	if err == nil {
		h.file.Write(msg)
	}
	return err
}

func (h *logrusFileHook) Levels() []logrus.Level {
	return logrus.AllLevels
}
