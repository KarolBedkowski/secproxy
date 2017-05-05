package admin

import (
	"html/template"
	"io/ioutil"
	"k.prv/secproxy/logging"
	res "k.prv/secproxy/resources"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	cacheLock    sync.Mutex
	cacheItems   = map[string]*template.Template{}
	logTemplates = logging.NewLogger("mw_gzip")
)

var funcMap = template.FuncMap{
	"namedurl":   GetNamedURL,
	"formatDate": FormatDate,
}

// FormatDate in template
func FormatDate(date time.Time, format string) string {
	if format == "" {
		format = "2006-01-02 15:04:05"
	}
	return date.Format(format)
}

// MainTemplateName contains name of main section in template (main template)
const MainTemplateName = "base"

func getTemplate(name string, nocache bool, filenames ...string) (tmpl *template.Template) {
	cacheLock.Lock()
	defer cacheLock.Unlock()

	ctemplate, ok := cacheItems[name]
	if !ok || nocache {
		ctemplate = template.New(name).Funcs(funcMap)
		for _, name := range filenames {
			if f, err := res.Assets.Open("templates/" + name); err == nil {
				defer f.Close()
				c, _ := ioutil.ReadAll(f)
				ctemplate = template.Must(ctemplate.Parse(string(c)))
			} else {
				logTemplates.
					With("err", err).
					With("template", name).
					Error("ERROR: renderTemplate get template error")
			}
		}
		if ctemplate.Lookup("scripts") == nil {
			ctemplate, _ = ctemplate.Parse("{{define \"scripts\"}}{{end}}")
		}
		if ctemplate.Lookup("header") == nil {
			ctemplate, _ = ctemplate.Parse("{{define \"header\"}}{{end}}")
		}
		if ctemplate.Lookup("tabs") == nil {
			ctemplate, _ = ctemplate.Parse("{{define \"tabs\"}}{{end}}")
		}
		cacheItems[name] = ctemplate
	}
	return ctemplate
}

// renderTemplate - render given templates.
func renderTemplate(w http.ResponseWriter, ctx PageContextInterface, name string, filenames ...string) {
	ctemplate := getTemplate(name, ctx.GetGlobals().DevMode, filenames...)
	if ctemplate == nil {
		return
	}
	err := ctemplate.ExecuteTemplate(w, MainTemplateName, ctx)
	if err != nil {
		logTemplates.
			With("err", err).
			With("template", name).
			With("filenames", filenames).
			Error("ERROR: renderTemplate execution failed")
	}
}

// StdTemplates contains list of templates included when rendering by renderTemplateStd
var StdTemplates = []string{"base.tmpl", "flash.tmpl"}

// renderTemplateStd render given templates + StdTemplates.
// Main section in template must be named 'base'.
// First template file name is used as template name.
func renderTemplateStd(w http.ResponseWriter, ctx PageContextInterface, filenames ...string) {
	filenames = append(filenames, StdTemplates...)
	logTemplates.With("filenames", filenames).
		Debug("renderTemplateStd")
	renderTemplate(w, ctx, filenames[0], filenames...)
}

func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			logTemplates.Error("ERROR: template %s not exists", name)
		}
		return false
	}
	return true
}
