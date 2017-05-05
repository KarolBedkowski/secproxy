package admin

import (
	"k.prv/secproxy/logging"
	"net/http"
	"strings"
)

var logAuth = logging.NewLogger("admin.auth")

type loginForm struct {
	Login    string
	Password string
	Back     string
}

func (lf *loginForm) Validate() string {
	lf.Login = strings.TrimSpace(lf.Login)
	if lf.Login == "" {
		return "missing login"
	}
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

	switch r.Method {

	case "POST":
		r.ParseForm()
		if err := decoder.Decode(&ctx.Form, r.Form); err != nil {
			log.With("err", err).
				Info("Login page: decode form error; form=%+v", r.Form)
			http.Error(w, http.StatusText(http.StatusInternalServerError)+" form error",
				http.StatusInternalServerError)
			return
		}

		log = log.With("user", ctx.Form.Login)

		if err := ctx.Form.Validate(); err != "" {
			log.With("err", err).
				Debug("Login page: validate form error; form=%+v", r.Form)
			break
		}

		user := bctx.Globals.GetUser(ctx.Form.Login)

		if user == nil || !user.CheckPassword(ctx.Form.Password) {
			log.Info("Login page: user pass failed")
			ctx.Message = "Wrong login and/or password"
			break
		}

		if !user.Active {
			log.Info("Login page: user account disable")
			ctx.Message = "Account inactive"
			break
		}

		ctx.AddFlashMessage("User log in", "info")
		ctx.Session.SetLoggedUser(newSessionUser(user.Login, user.Role))
		ctx.Save()
		log.Info("Login page: user log in")

		if back := ctx.Form.Back; back != "" {
			log.Debug("Login page: back after login to %v", back)
			http.Redirect(w, r, back, http.StatusFound)
		} else {
			http.Redirect(w, r, "/", http.StatusFound)
		}
		return
	}

	ctx.Save()
	renderTemplate(w, ctx, "login", "login.tmpl", "flash.tmpl")
}

func logoffHandler(w http.ResponseWriter, r *http.Request) {
	clearSession(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}
