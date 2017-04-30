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

	log := logAuth.WithRequest(r)

	if r.Method == "POST" {
		r.ParseForm()
		if err := decoder.Decode(&ctx.Form, r.Form); err != nil {
			logAuth.WithRequest(r).With("err", err).
				Info("admin.loginPageHandler decode form error; form=%+v", r.Form)
			http.Error(w, http.StatusText(http.StatusInternalServerError)+" form error",
				http.StatusInternalServerError)
			return
		}
		if err := ctx.Form.Validate(); err != "" {
			log.With("err", err).
				Debug("admin.loginPageHandler validate form error; form=%+v", r.Form)
			RenderTemplate(w, ctx, "login", "login.tmpl", "flash.tmpl")
			return
		}
		user := bctx.Globals.GetUser(ctx.Form.Login)
		if user != nil {
			log = log.With("user", user.Login)
		}
		if user == nil || !user.CheckPassword(ctx.Form.Password) {
			log.Info("admin.loginPageHandler user pass failed")
			ctx.Message = "Wrong login and/or password"
			RenderTemplate(w, ctx, "login", "login.tmpl", "flash.tmpl")
			return
		}
		if !user.Active {
			log.Info("admin.loginPageHandler user account disable")
			ctx.Message = "Account inactive"
			RenderTemplate(w, ctx, "login", "login.tmpl", "flash.tmpl")
			return
		}
		ctx.AddFlashMessage("User log in", "info")
		ctx.Session.SetLoggedUser(NewSessionUser(user.Login, user.Role))
		ctx.Save()
		log.Info("user log in")
		if back := ctx.Form.Back; back != "" {
			log.Debug("admin.loginPageHandler back; dst=%v", back)
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
