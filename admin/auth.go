package admin

import (
	"k.prv/secproxy/logging"
	"net/http"
)

var logAuth = logging.NewLogger("admin.auth")

type loginForm struct {
	Login    string
	Password string
	Back     string
}

func (lf *loginForm) Validate() string {
	return ""
}

func loginPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Form    loginForm
		Message string
	}{
		BasePageContext: bctx,
		Form:            loginForm{},
		Message:         "",
	}
	if r.Method == "POST" {
		r.ParseForm()
		if err := decoder.Decode(&ctx.Form, r.Form); err != nil {
			logging.LogForRequest(logAuth, r).Error("admin.loginPageHandler decode form error", "err", err, "form", r.Form)
			http.Error(w, http.StatusText(http.StatusInternalServerError)+" form error",
				http.StatusInternalServerError)
			return
		}
		if err := ctx.Form.Validate(); err != "" {
			logging.LogForRequest(logAuth, r).Debug("admin.loginPageHandler validate form error", "err", err, "form", r.Form)
			RenderTemplate(w, ctx, "login", "login.tmpl", "flash.tmpl")
			return
		}
		user := bctx.Globals.GetUser(ctx.Form.Login)
		if user == nil || !user.CheckPassword(ctx.Form.Password) {
			logging.LogForRequest(logAuth, r).Info("admin.loginPageHandler user pass failed", "user", user)
			ctx.Message = "Wrong login and/or password"
			RenderTemplate(w, ctx, "login", "login.tmpl", "flash.tmpl")
			return
		}
		ctx.AddFlashMessage("User log in", "info")
		ctx.Session.SetLoggedUser(NewSessionUser(user.Login, user.Role))
		ctx.Save()
		if back := ctx.Form.Back; back != "" {
			logging.LogForRequest(logAuth, r).Debug("admin.loginPageHandler back", "dst", back)
			http.Redirect(w, r, back, http.StatusFound)
		} else {
			http.Redirect(w, r, "/", http.StatusFound)
		}
	} else {
		RenderTemplate(w, ctx, "login", "login.tmpl", "flash.tmpl")
	}
}

func logoffHandler(w http.ResponseWriter, r *http.Request) {
	ClearSession(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}
