package admin

import (
	"github.com/gorilla/mux"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"net/http"
)

var logUsers = logging.NewLogger("admin.users")

func initUsersHandlers(globals *config.Globals, parentRotuer *mux.Route) {
	router := parentRotuer.Subrouter()
	router.HandleFunc("/user/{login}", securityContextHandler(userPageHandler, globals, "ADMIN"))
	router.HandleFunc("/user/", securityContextHandler(userPageHandler, globals, "ADMIN"))
	router.HandleFunc("/", securityContextHandler(usersPageHandler, globals, "ADMIN"))
}

func usersPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Users []*config.User
	}{bctx, bctx.Globals.GetUsers()}
	renderTemplateStd(w, ctx, "users/index.tmpl")
}

type (
	userForm struct {
		config.User
		NewPassword  string
		NewPasswordC string
		Errors       map[string]string `schema:"-"`
	}
)

func (f userForm) Validate(globals *config.Globals, newUser bool) (errors map[string]string) {
	errors = f.User.Validate()
	if len(errors) == 0 && newUser {
		// check login uniquess
		if u := globals.GetUser(f.Login); u != nil {
			errors["Login"] = "Login already used"
		}
	}
	if f.NewPassword != "" && f.NewPasswordC != f.NewPassword {
		errors["NewPassword"] = "Passwords not match"
	}
	return errors
}

func userPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Form     userForm
		AllRoles []string
	}{
		BasePageContext: bctx,
		AllRoles:        []string{"ADMIN", "USER"},
	}

	vars := mux.Vars(r)
	login := ""
	if l, ok := vars["login"]; ok {
		login = l
	}
	log := logUsers.WithRequest(r).With("user", bctx.UserLogin()).With("login", login)

	switch r.Method {
	case "POST":
		r.ParseForm()
		if err := decoder.Decode(&ctx.Form, r.Form); err != nil {
			log.With("err", err).
				Info("User edit: decode form error; form=%+v", r.Form)
			break
		}

		if login != "" && ctx.Form.User.Login != login {
			log.Info("User edit: login != form.login")
			http.Error(w, "Wrong/changed login", http.StatusBadRequest)
			return
		}

		if errors := ctx.Form.Validate(bctx.Globals, login == ""); len(errors) > 0 {
			ctx.Form.Errors = errors
			break
		}

		if ctx.Form.NewPassword != "" {
			ctx.Form.User.UpdatePassword(ctx.Form.NewPassword)
		}

		if ctx.Form.User.Login == "admin" {
			// can't disable admin account
			ctx.Form.User.Active = true
		}

		bctx.Globals.SaveUser(&ctx.Form.User)
		ctx.AddFlashMessage("User saved", "success")
		ctx.Save()
		log.Info("User edit: user saved")
		http.Redirect(w, r, "/users/", http.StatusFound)
		return
	case "GET":
		if login != "" {
			if user := bctx.Globals.GetUser(login); user != nil {
				ctx.Form.User = *user
			} else {
				log.Error("admin.userPageHandler user %s not found", login)
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
		}
	}
	ctx.Save()
	renderTemplateStd(w, ctx, "users/user.tmpl")
}

type (
	chpassForm struct {
		CurrentPass  string
		NewPassword  string
		NewPasswordC string
		Errors       map[string]string `schema:"-"`
	}
)

func chpassPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Form chpassForm
	}{
		BasePageContext: bctx,
	}

	log := logUsers.WithRequest(r)

	suser, ok := bctx.Session.GetLoggedUser()
	if !ok || suser == nil {
		log.Info("Change password: user not logged")
		http.Error(w, "Not logged user", http.StatusBadRequest)
		return
	}

	log = log.With("user", bctx.UserLogin())

	switch r.Method {
	case "POST":
		r.ParseForm()
		if err := decoder.Decode(&ctx.Form, r.Form); err != nil {
			log.With("err", err).
				Error("Change password: decode form error; form=%+v", r.Form)
			break
		}

		user := bctx.Globals.GetUser(suser.Login)
		if user == nil {
			log.Error("Change password: user %s not found", suser.Login)
			http.Error(w, "Bad user", http.StatusBadRequest)
			return
		}

		ctx.Form.Errors = make(map[string]string)
		if !user.CheckPassword(ctx.Form.CurrentPass) {
			ctx.Form.Errors["CurrentPass"] = "Wrong password"
			break
		}

		if ctx.Form.NewPasswordC != ctx.Form.NewPassword {
			ctx.Form.Errors["NewPassword"] = "Passwords not match"
			break
		}

		user.UpdatePassword(ctx.Form.NewPassword)
		bctx.Globals.SaveUser(user)
		ctx.AddFlashMessage("Password updated", "success")
		ctx.Save()
		log.Info("Change password: password for %s changed", suser.Login)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	ctx.Save()
	renderTemplateStd(w, ctx, "users/chpass.tmpl")
}
