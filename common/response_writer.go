package common

import (
	"net/http"
)

// ResponseWriter response writer with status
type ResponseWriter struct {
	http.ResponseWriter
	Status int
}

// WriteHeader store status of request
func (writer *ResponseWriter) WriteHeader(status int) {
	writer.ResponseWriter.WriteHeader(status)
	writer.Status = status
}
