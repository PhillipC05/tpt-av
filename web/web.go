// Package web embeds and serves the TPT-AV single-page dashboard.
package web

import (
	"io/fs"
	"net/http"

	"embed"
)

//go:embed static
var assets embed.FS

// Register mounts the dashboard on the given mux:
//
//	GET /            → the dashboard (index.html)
//	GET /static/...  → embedded static assets
//
// The dashboard talks to the Guard (:7731) and Patrol (:7732) APIs directly
// from the browser, so it can be served by either daemon.
func Register(mux *http.ServeMux) {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		panic("web: embedded static dir missing: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))
	mux.Handle("GET /static/", http.StripPrefix("/static/", fileServer))

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		data, err := assets.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "dashboard not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})
}
