package web

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"
)

//go:embed dist/*
var files embed.FS

func Handler() http.Handler {
	sub, err := fs.Sub(files, "dist")
	if err != nil {
		return http.NotFoundHandler()
	}
	return spaHandler{root: sub, files: http.FileServer(http.FS(sub))}
}

type spaHandler struct {
	root  fs.FS
	files http.Handler
}

func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := cleanAssetPath(r.URL.Path)
	if name != "" && name != "index.html" {
		f, err := h.root.Open(name)
		if err == nil {
			stat, statErr := f.Stat()
			_ = f.Close()
			if statErr == nil && !stat.IsDir() {
				h.files.ServeHTTP(w, r)
				return
			}
		}
		if isStaticAsset(name) {
			http.NotFound(w, r)
			return
		}
	}
	h.serveIndex(w, r)
}

func (h spaHandler) serveIndex(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(h.root, "index.html")
	if err != nil {
		http.Error(w, "web UI is not built", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(b))
}

func cleanAssetPath(raw string) string {
	clean := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(raw, "/")), "/")
	if clean == "." {
		return ""
	}
	return clean
}

func isStaticAsset(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".js", ".css", ".svg", ".ico", ".png", ".jpg", ".jpeg", ".webp", ".woff", ".woff2":
		return true
	default:
		return false
	}
}
