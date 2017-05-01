// Handle gziped static files
// Based on: https://github.com/joaodasilva/go-gzip-file-server

package admin

import (
	"io"
	"k.prv/secproxy/logging"
	res "k.prv/secproxy/resources"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var logMwGzip = logging.NewLogger("mw_gzip")

type gzipFileHandler struct {
	fs           http.FileSystem
	disableCache bool
}

func (h *gzipFileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/") {
		r.URL.Path = "/" + r.URL.Path
	}
	serveFile(w, r, h.fs, path.Clean(r.URL.Path), true, h.disableCache)
}

// FileServer - net.http.FileServer + serving <file>.gz when exists instead of requested
// file.
// When disableCache - add header Cache-Control to response.
func FileServer(root http.FileSystem, disableCache bool) http.Handler {
	return &gzipFileHandler{root, disableCache}
}

// ServeFile - net.http.ServeFile but first try to serve gzip file when exists <file>.gz
func ServeFile(w http.ResponseWriter, r *http.Request, name string, disableCache bool) {
	dir, file := filepath.Split(name)
	serveFile(w, r, http.Dir(dir), file, false, disableCache)
}

func serveFile(w http.ResponseWriter, r *http.Request, fs http.FileSystem,
	name string, redirect bool, disableCache bool) {

	// try to serve gziped file; ignore request for gz files
	if !strings.HasSuffix(strings.ToLower(name), ".gz") && supportsGzip(r) {
		if file, stat, err := open(fs, name+".gz"); file != nil && err == nil {
			defer file.Close()
			setContentType(w, name, file)
			w.Header().Set("Content-Encoding", "gzip")
			if disableCache {
				w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0")
				w.Header().Set("Pragma", "no-cache")
			} else {
				w.Header().Set("Cache-Control", "must_revalidate, private, max-age=604800")
			}
			http.ServeContent(w, r, name, stat.ModTime(), file)
			return
		}
	}

	// serve requested file
	if file, stat, err := open(fs, name); file != nil && err == nil {
		defer file.Close()
		if disableCache {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0")
			w.Header().Set("Pragma", "no-cache")
		} else {
			w.Header().Set("Cache-Control", "must_revalidate, private, max-age=604800")
		}
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), file)
	} else {
		logMwGzip.
			With("err", err).
			With("asset", name).
			Debug("MW GZIP: Asset open error")
		http.NotFound(w, r)
	}
}

func supportsGzip(r *http.Request) bool {
	for _, encodings := range r.Header["Accept-Encoding"] {
		for _, encoding := range strings.Split(encodings, ",") {
			if encoding == "gzip" {
				return true
			}
		}
	}
	return false
}

func setContentType(w http.ResponseWriter, name string, file http.File) {
	t := mime.TypeByExtension(filepath.Ext(name))
	if t == "" {
		var buffer [512]byte
		n, _ := io.ReadFull(file, buffer[:])
		t = http.DetectContentType(buffer[:n])
		if _, err := file.Seek(0, os.SEEK_SET); err != nil {
			http.Error(w, "Can't seek", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", t)
}

// open file and return File and FileInfo; ignore directories.
func open(fs http.FileSystem, name string) (file http.File, stat os.FileInfo, err error) {
	file, err = res.Assets.Open("static" + name)
	if err != nil {
		return
	}
	stat, err = file.Stat()
	if err != nil || stat.IsDir() { // ignore dirs
		file.Close()
		file = nil
	}
	return
}
