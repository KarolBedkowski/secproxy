package admin

import (
	"k.prv/secproxy/common"
	"k.prv/secproxy/config"
	"net/http"
	"strings"
)

// PageContextInterface define interface for page context
type PageContextInterface interface {
	GetGlobals() *config.Globals
}

// BasePageContext context for pages
type BasePageContext struct {
	Session        *mySession
	ResponseWriter http.ResponseWriter
	Request        *http.Request
	CsrfToken      string
	FlashMessages  map[string][]interface{}
	Globals        *config.Globals
}

// FlashKind keep types of flashes
var FlashKind = []string{"error", "info", "success"}

// newBasePageContext create base page context for request
func newBasePageContext(globals *config.Globals, w http.ResponseWriter, r *http.Request) *BasePageContext {
	s := getSessionStore(w, r)
	csrfToken := s.Values[CONTEXTCSRFTOKEN]
	if csrfToken == nil {
		csrfToken = CreateNewCsrfToken()
		s.Values[CONTEXTCSRFTOKEN] = csrfToken
	}

	ctx := &BasePageContext{
		ResponseWriter: w,
		Request:        r,
		Session:        s,
		CsrfToken:      csrfToken.(string),
		FlashMessages:  make(map[string][]interface{}),
		Globals:        globals,
	}

	for _, kind := range FlashKind {
		if flashes := ctx.Session.Flashes(kind); flashes != nil && len(flashes) > 0 {
			ctx.FlashMessages[kind] = flashes
		}
	}

	ctx.Save()
	return ctx
}

// GetGlobals returns global object from context
func (ctx *BasePageContext) GetGlobals() *config.Globals {
	return ctx.Globals
}

// GetFlashMessage for current context
func (ctx *BasePageContext) GetFlashMessage() map[string][]interface{} {
	return ctx.FlashMessages
}

// AddFlashMessage to context
func (ctx *BasePageContext) AddFlashMessage(msg string, kind string) {
	ctx.Session.AddFlash(msg, kind)
}

// AddFlashMessageErr in dev mode show error
func (ctx *BasePageContext) AddFlashMessageErr(msg string, err string, kind string) {
	if ctx.GetGlobals().DevMode {
		ctx.Session.AddFlash(msg+" ("+err+")", kind)
	} else {
		ctx.Session.AddFlash(msg, kind)
	}
}

// Save session by page context
func (ctx *BasePageContext) Save() error {
	return saveSession(ctx.ResponseWriter, ctx.Request)
}

// UserLogged check is current session belong to logged user
func (ctx *BasePageContext) UserLogged() bool {
	user, ok := ctx.Session.GetLoggedUser()
	return ok && user != nil
}

// UserLogin returns current logged user login
func (ctx *BasePageContext) UserLogin() string {
	if user, ok := ctx.Session.GetLoggedUser(); ok && user != nil {
		return user.Login
	}
	return ""
}

// HasUserRole check is current user is logged and have given role
func (ctx *BasePageContext) HasUserRole(role string) bool {
	user, ok := ctx.Session.GetLoggedUser()
	return ok && user.Role == role
}

// URLStartsWith returns true when current url starts with prefix
func (ctx *BasePageContext) URLStartsWith(prefix string) bool {
	return strings.HasPrefix(ctx.Request.URL.Path, prefix)
}

// BaseContextHandlerFunc - handler function called by HandleWithContext and HandleWithContextSec
type BaseContextHandlerFunc func(w http.ResponseWriter, r *http.Request, ctx *BasePageContext)

// ContextHandler create BasePageContext for request
func ContextHandler(h BaseContextHandlerFunc, globals *config.Globals) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := newBasePageContext(globals, w, r)
		h(w, r, ctx)
	})
}

// securityContextHandler create BasePageContext for request and check user permissions.
func securityContextHandler(h BaseContextHandlerFunc, globals *config.Globals, reqRole string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := newBasePageContext(globals, w, r)
		user, ok := ctx.Session.GetLoggedUser()
		if ok {
			if reqRole == "" {
				h(w, r, ctx)
				return
			}

			if user.Role == reqRole {
				h(w, r, ctx)
				return
			}

			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		//redirect to login
		url := GetNamedURL("auth-login")
		url += common.BuildQuery("back", r.URL.String())
		http.Redirect(w, r, url, 302)
	})
}
