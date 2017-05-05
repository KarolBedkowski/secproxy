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

func initCertsHandlers(globals *config.Globals, parentRotuer *mux.Route) {
	router := parentRotuer.Subrouter()
	router.HandleFunc("/", securityContextHandler(certsPageHandler, globals, "ADMIN"))
	router.HandleFunc("/upload", securityContextHandler(certUploadPageHandler, globals, "ADMIN")).Methods("POST")
	router.HandleFunc("/delete", securityContextHandler(certDeletePageHandler, globals, "ADMIN"))
}

func certsPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	ctx := &struct {
		*BasePageContext
		Certs []string
	}{
		bctx,
		append(bctx.Globals.FindCerts(), bctx.Globals.FindKeys()...),
	}

	renderTemplateStd(w, ctx, "certs.tmpl")
}

func certUploadPageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	r.ParseMultipartForm(32 << 20)
	log := logCerts.WithRequest(r).With("user", bctx.UserLogin())

	ffile, fhandler, err := r.FormFile("uploadfile")
	if err != nil {
		log.With("err", err).Info("Upload cert: get form file error")
		bctx.AddFlashMessageErr("Upload file error", err.Error(), "error")
		bctx.Save()
		http.Redirect(w, r, "/certs/", http.StatusFound)
		return
	}
	defer ffile.Close()

	fout, err := os.OpenFile(
		path.Join(bctx.Globals.Config.CertsDir, fhandler.Filename),
		os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		log.With("err", err).
			Warn("ERROR: upload cert: open file %s error", fhandler.Filename)
		bctx.AddFlashMessageErr("Upload file error", err.Error(), "error")
		bctx.Save()
		http.Redirect(w, r, "/certs/", http.StatusFound)
		return
	}
	defer fout.Close()

	if _, err := io.Copy(fout, ffile); err == nil {
		log.With("filename", fhandler.Filename).Info("Upload cert: success")
		bctx.AddFlashMessage("Upload file success", "success")
	} else {
		log.With("err", err).With("filename", fhandler.Filename).
			Warn("ERROR: Upload cert: upload file error")
		bctx.AddFlashMessageErr("Upload file error", err.Error(), "error")
	}
	bctx.Save()
	http.Redirect(w, r, "/certs/", http.StatusFound)
}

func certDeletePageHandler(w http.ResponseWriter, r *http.Request, bctx *BasePageContext) {
	r.ParseForm()
	log := logCerts.WithRequest(r).With("user", bctx.UserLogin())
	certname := ""
	if certnames, ok := r.Form["c"]; ok && len(certnames) > 0 {
		certname = certnames[0]
	}

	if certname == "" {
		log.Debug("Delete certificate: error - missing certname; form=%+v", r.Form)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	log = log.With("certname", certname)

	if epname, used := bctx.Globals.CertUsed(certname); used {
		log.Info("Delete certificate: error - cert used in endpoint=%s", epname)
		bctx.AddFlashMessage("File is used in "+epname+" - can't be deleted", "error")
		bctx.Save()
		http.Redirect(w, r, "/certs/", http.StatusFound)
		return
	}

	certname, _ = filepath.Abs(certname)
	certname = filepath.Clean(certname)
	certsdir, _ := filepath.Abs(bctx.Globals.Config.CertsDir)
	certsdir = filepath.Clean(certsdir)

	if stat, err := os.Stat(certname); certname == "" || err != nil ||
		stat.IsDir() || !strings.HasPrefix(certname, certsdir) || certname == certsdir {
		log.With("err", err).Info("Delete certificate error - invalid cert; %+v", stat)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err := os.Remove(certname); err == nil {
		log.Info("Delete certificate: success")
		bctx.AddFlashMessage("File deleted", "success")
	} else {
		log.With("err", err).Warn("ERROR: Delete certificate: error")
		bctx.AddFlashMessageErr("File delete error", err.Error(), "error")
	}

	bctx.Save()
	http.Redirect(w, r, "/certs/", http.StatusFound)
}
