package admin

import (
	"github.com/gorilla/mux"
	"io"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var logCerts = logging.NewLogger("admin.certs")

// Init - Initialize application
func InitCertsHandlers(globals *config.Globals, parentRotuer *mux.Route) {
	router := parentRotuer.Subrouter()
	router.HandleFunc("/", SecurityContextHandler(certsPageHandler, globals, "ADMIN"))
	router.HandleFunc("/upload", SecurityContextHandler(certUploadPageHandler, globals, "ADMIN")).Methods("POST")
	router.HandleFunc("/delete", SecurityContextHandler(certDeletePageHandler, globals, "ADMIN"))
}

func certsPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Certs []string
	}{
		bctx,
		bctx.Globals.FindCerts(),
	}
	RenderTemplateStd(w, ctx, "certs.tmpl")
}

func certUploadPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	r.ParseMultipartForm(32 << 20)
	file, handler, err := r.FormFile("uploadfile")
	if err != nil {
		logging.LogForRequest(logCerts, r).Warn("certUploadPageHandler - get form file error",
			"err", err)
		bctx.AddFlashMessage("Upload file error: "+err.Error(), "error")
		bctx.Save()
		http.Redirect(w, r, "/certs/", http.StatusFound)
		return
	}
	defer file.Close()
	f, err := os.OpenFile(path.Join(bctx.Globals.Config.CertsDir, handler.Filename), os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		logging.LogForRequest(logCerts, r).Warn("certUploadPageHandler - open file error",
			"certname", handler.Filename, "user", bctx.UserLogin(), "err", err)
		bctx.AddFlashMessage("Upload file error: "+err.Error(), "error")
		http.Redirect(w, r, "/certs/", http.StatusFound)
		bctx.Save()
		return
	}
	defer f.Close()
	if _, err := io.Copy(f, file); err == nil {
		logging.LogForRequest(logCerts, r).Info("certUploadPageHandler upload success",
			"certname", handler.Filename, "user", bctx.UserLogin())
		bctx.AddFlashMessage("Upload file success", "success")
	} else {
		logging.LogForRequest(logCerts, r).Warn("certUploadPageHandler upload error",
			"certname", handler.Filename, "user", bctx.UserLogin(), "err", err)
		bctx.AddFlashMessage("Upload file error: "+err.Error(), "error")
	}
	bctx.Save()
	http.Redirect(w, r, "/certs/", http.StatusFound)
}

func certDeletePageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	r.ParseForm()
	certname := ""
	if certnames, ok := r.Form["c"]; ok && len(certnames) > 0 {
		certname = certnames[0]
	}
	if certname == "" {
		logging.LogForRequest(logCerts, r).Warn("certDeletePageHandler missing certname", "form", r.Form)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if epname, used := bctx.Globals.CertUsed(certname); used {
		logging.LogForRequest(logCerts, r).Info("certDeletePageHandler - cert used", "certname", certname, "endpoint", epname)
		bctx.AddFlashMessage("File is used in "+epname+" - can't be deleted", "error")
		bctx.Save()
		http.Redirect(w, r, "/certs/", http.StatusFound)
		return
	}

	certname, _ = filepath.Abs(certname)
	certname = filepath.Clean(certname)
	certsdir, _ := filepath.Abs(bctx.Globals.Config.CertsDir)
	certsdir = filepath.Clean(certsdir)
	if certname == "" || !strings.HasPrefix(certname, certsdir) || certname == certsdir {
		logging.LogForRequest(logCerts, r).Warn("certDeletePageHandler invalid cert",
			"certname", certname, "form", r.Form, "certsdir", certsdir)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := os.Remove(certname); err == nil {
		logging.LogForRequest(logCerts, r).Info("certDeletePageHandler cert deleted",
			"certname", certname, "user", bctx.UserLogin())
		bctx.AddFlashMessage("File deleted", "success")
	} else {
		logging.LogForRequest(logCerts, r).Warn("certDeletePageHandler cert deleted error",
			"certname", certname, "err", err, "user", bctx.UserLogin())
		bctx.AddFlashMessage("File delete error: "+err.Error(), "error")
	}
	bctx.Save()
	http.Redirect(w, r, "/certs/", http.StatusFound)
}
