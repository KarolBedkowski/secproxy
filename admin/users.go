package admin

import (
	"github.com/gorilla/mux"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"net/http"
)

var logUsers = logging.NewLogger("admin.users")

// Init - Initialize application
func InitUsersHandlers(globals *config.Globals, parentRotuer *mux.Route) {
	router := parentRotuer.Subrouter()
	router.HandleFunc("/{login}", SecurityContextHandler(userPageHandler, globals, "ADMIN"))
	router.HandleFunc("/", SecurityContextHandler(usersPageHandler, globals, "ADMIN"))
}

func usersPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Users []*config.User
	}{bctx, bctx.Globals.GetUsers()}
	RenderTemplateStd(w, ctx, "users/index.tmpl")
}

type (
	userForm struct {
		*config.User
		NewPassword  string
		NewPasswordC string
		Errors       map[string]string `schema:"-"`
		Method       string            `schema:"_method"`
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
	vars := mux.Vars(r)
	ctx := &struct {
		*BasePageContext
		Form     userForm
		AllRoles []string
	}{
		BasePageContext: bctx,
		AllRoles:        []string{"ADMIN", "USER"},
	}
	if r.Method == "POST" && r.FormValue("_method") != "" {
		r.Method = r.FormValue("_method")
	}
	login, ok := vars["login"]
	if !ok || login == "" {
		logging.LogForRequest(logUsers, r).Error("admin.userPageHandler missing login", "vars", vars)
		http.Error(w, "Missing login", http.StatusBadRequest)
		return
	}

	newUser := login == "<new>"

	if !newUser {
		if user := bctx.Globals.GetUser(login); user != nil {
			ctx.Form.User = user.Clone()
		} else {
			logging.LogForRequest(logUsers, r).Error("admin.userPageHandler user not found", "login", login)
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
	} else {
		ctx.Form.User = &config.User{}
	}
	switch r.Method {
	case "POST":
		r.ParseForm()
		var currLogin = ctx.Form.User.Login
		ctx.Form.User.Active = false // post not send unchecked checkboxes
		if err := decoder.Decode(&ctx.Form, r.Form); err != nil {
			logging.LogForRequest(logUsers, r).Error("admin.userPageHandler decode form error ", "err", err, "form", r.Form)
			break
		}
		if !newUser && ctx.Form.User.Login != login {
			logging.LogForRequest(logUsers, r).Error("admin.userPageHandler login != form.login ", "login", login, "login-form", ctx.Form.User.Login)
			http.Error(w, "Wrong/changed login", http.StatusBadRequest)
			return
		}
		if !newUser && ctx.Form.User.Login != currLogin {
			logging.LogForRequest(logUsers, r).Warn("login changed - reverting")
			ctx.Form.User.Login = currLogin
		}
		if errors := ctx.Form.Validate(bctx.Globals, newUser); len(errors) > 0 {
			ctx.Form.Errors = errors
			break
		}
		if ctx.Form.NewPassword != "" {
			ctx.Form.User.UpdatePassword(ctx.Form.NewPassword)
		}
		bctx.Globals.SaveUser(ctx.Form.User)
		ctx.AddFlashMessage("User saved", "success")
		ctx.Save()
		http.Redirect(w, r, "/users/", http.StatusFound)
		return
	}
	ctx.Save()
	RenderTemplateStd(w, ctx, "users/user.tmpl")
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
		logging.LogForRequest(logUsers, r).Error("admin.chpassPageHandler user not logged")
		http.Error(w, "Not logged user", http.StatusBadRequest)
		return
	}

	log = log.With("user", bctx.UserLogin())

	switch r.Method {
	case "POST":
		r.ParseForm()
		if err := decoder.Decode(&ctx.Form, r.Form); err != nil {
			log.With("err", err).Error("admin.chpassPageHandler decode form error; form=%+v", r.Form)
			break
		}

		user := bctx.Globals.GetUser(suser.Login)
		if user == nil {
			log.Error("admin.chpassPageHandler user %s not found", suser.Login)
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

		if user.Login == "admin" {
			user.Active = true
		}

		user.UpdatePassword(ctx.Form.NewPassword)
		bctx.Globals.SaveUser(user)
		ctx.AddFlashMessage("Password updated", "success")
		ctx.Save()
		log.Error("admin.chpassPageHandler password fror %s changed", suser.Login)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	ctx.Save()
	RenderTemplateStd(w, ctx, "users/chpass.tmpl")
}
