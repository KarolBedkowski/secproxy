package admin

import (
	"k.prv/secproxy/common"
	"k.prv/secproxy/config"
	"net/http"
)

type PageContextInterface interface {
	GetGlobals() *config.Globals
}

// BasePageContext context for pages
type BasePageContext struct {
	Session        *MySession
	ResponseWriter http.ResponseWriter
	Request        *http.Request
	CsrfToken      string
	FlashMessages  map[string][]interface{}
	Globals        *config.Globals
}

// Types of flashes
var FlashKind = []string{"error", "info", "success"}

// NewBasePageContext create base page context for request
func NewBasePageContext(globals *config.Globals, w http.ResponseWriter, r *http.Request) *BasePageContext {
	s := GetSessionStore(w, r)
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

func (ctx *BasePageContext) GetGlobals() *config.Globals {
	return ctx.Globals
}

// GetFlashMessage for current context
func (ctx *BasePageContext) GetFlashMessage() map[string][]interface{} {
	return ctx.FlashMessages
}

// AddFlashMessage to context
func (ctx *BasePageContext) AddFlashMessage(msg interface{}, kind ...string) {
	if len(kind) > 0 {
		ctx.Session.AddFlash(msg, kind...)
	} else {
		ctx.Session.AddFlash(msg, "info")
	}
}

// Save session by page context
func (ctx *BasePageContext) Save() error {
	return SaveSession(ctx.ResponseWriter, ctx.Request)
}

func (ctx *BasePageContext) UserLogged() bool {
	user, ok := ctx.Session.GetLoggedUser()
	return ok && user != nil
}

// BaseContextHandlerFunc - handler function called by HandleWithContext and HandleWithContextSec
type BaseContextHandlerFunc func(w http.ResponseWriter, r *http.Request, ctx *BasePageContext)

// ContextHandler create BasePageContext for request
func ContextHandler(h BaseContextHandlerFunc, globals *config.Globals) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := NewBasePageContext(globals, w, r)
		h(w, r, ctx)
	})
}

// SecurityContextHandler create BasePageContext for request and check user permissions.
func SecurityContextHandler(h BaseContextHandlerFunc, globals *config.Globals, reqRole string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := NewBasePageContext(globals, w, r)
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
