package admin

import (
	"k.prv/secproxy/common"
	log "k.prv/secproxy/logging"
	"net/http"
)

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
	log.Debug("admin.loginPageHandler start ", common.RequestLogEntry(r), " ", r.Form)
	if r.Method == "POST" {
		r.ParseForm()
		if err := decoder.Decode(&ctx.Form, r.Form); err != nil {
			log.Error("admin.loginPageHandler decode form error ", err, common.RequestLogEntry(r), " ", r.Form)
			http.Error(w, http.StatusText(http.StatusInternalServerError)+" form error",
				http.StatusInternalServerError)
			return
		}
		if err := ctx.Form.Validate(); err != "" {
			log.Debug("admin.loginPageHandler validate form error ", err, common.RequestLogEntry(r), " ", r.Form)
			RenderTemplate(w, ctx, "login", "login.tmpl", "flash.tmpl")
			return
		}
		user := bctx.Globals.GetUser(ctx.Form.Login)
		if user == nil || !user.CheckPassword(ctx.Form.Password) {
			log.Info("admin.loginPageHandler user valudation failed: ", user)
			ctx.Message = "Wrong login and/or password"
			RenderTemplate(w, ctx, "login", "login.tmpl", "flash.tmpl")
			return
		}
		ctx.AddFlashMessage("User log in", "info")
		ctx.Session.SetLoggedUser(NewSessionUser(user.Login, user.Role))
		ctx.Save()
		if back := ctx.Form.Back; back != "" {
			log.Debug("admin.loginPageHandler validate redirect to back: ", back)
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
