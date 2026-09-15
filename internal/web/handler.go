package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

func Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := templateFS.ReadFile("templates/dashboard.html")
		if err != nil {
			http.Error(w, "template not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/static/", http.FileServer(http.FS(staticSub)))

	return mux
}