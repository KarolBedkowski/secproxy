package admin

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

// csrf tokens len
const csrftokenlen = 64

// csrf tokens name in context
const CONTEXTCSRFTOKEN = "csrf_token"

// csrf tokens name formms
const FORMCSRFTOKEN = "BasePageContext.CsrfToken"

// alternative csrf token name
const FORMCSRFTOKEN2 = "CsrfToken"

// CsrfHandler - middleware verify CSRF token in request.
func CsrfHandler(h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := GetSessionStore(w, r)
		csrfToken := sess.Values[CONTEXTCSRFTOKEN]
		if r.Method == "POST" && r.FormValue(FORMCSRFTOKEN) != csrfToken && r.FormValue(FORMCSRFTOKEN2) != csrfToken {
			http.Error(w, "Fobidden/CSRF", http.StatusForbidden)
			//h.ServeHTTP(w, r)
		} else {
			// Remove token from request params
			delete(r.Form, FORMCSRFTOKEN)
			delete(r.Form, FORMCSRFTOKEN2)
			h.ServeHTTP(w, r)
		}
	})
}

// CreateNewCsrfToken create new CSRF token
func CreateNewCsrfToken() string {
	token := make([]byte, csrftokenlen)
	rand.Read(token)
	csrfToken := base64.StdEncoding.EncodeToString(token)
	return csrfToken
}
