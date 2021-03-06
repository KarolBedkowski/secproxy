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
	cacheLock  sync.Mutex
	cacheItems = map[string]*template.Template{}
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

func getTemplate(name string, debug bool, filenames ...string) (tmpl *template.Template) {
	cacheLock.Lock()
	defer cacheLock.Unlock()

	ctemplate, ok := cacheItems[name]
	if !ok || debug {
		ctemplate = template.New(name).Funcs(funcMap)
		for _, name := range filenames {
			if f, err := res.Assets.Open("templates/" + name); err == nil {
				defer f.Close()
				c, _ := ioutil.ReadAll(f)
				ctemplate = template.Must(ctemplate.Parse(string(c)))
			} else {
				log.Error("RenderTemplate get template error", "name", name, "err", err)
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

// RenderTemplate - render given templates.
func RenderTemplate(w http.ResponseWriter, ctx PageContextInterface, name string, filenames ...string) {
	ctemplate := getTemplate(name, logging.DebugLevel() > 0, filenames...)
	if ctemplate == nil {
		return
	}
	err := ctemplate.ExecuteTemplate(w, MainTemplateName, ctx)
	if err != nil {
		log.Error("RenderTemplate execution failed", "err", err, "name", name, "filenames", filenames)
	}
}

// StdTemplates contains list of templates included when rendering by RenderTemplateStd
var StdTemplates = []string{"base.tmpl", "flash.tmpl"}

// RenderTemplateStd render given templates + StdTemplates.
// Main section in template must be named 'base'.
// First template file name is used as template name.
func RenderTemplateStd(w http.ResponseWriter, ctx PageContextInterface, filenames ...string) {
	filenames = append(filenames, StdTemplates...)
	log.Debug("RenderTemplateStd", "filenames", filenames)
	RenderTemplate(w, ctx, filenames[0], filenames...)
}

func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			log.Error("template not exists", "name", name)
		}
		return false
	}
	return true
}
