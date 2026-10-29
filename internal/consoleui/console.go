// SPDX-License-Identifier: BUSL-1.1
// Package consoleui serves only the compiled, embedded operator console.
package consoleui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed dist
var assets embed.FS
var slots = make(chan struct{}, 8)

func Serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Console asset capacity is busy. Retry shortly.", 503)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Use GET or HEAD.", 405)
		return
	}
	if r.URL.Path == "/" || r.URL.Path == "/console" {
		http.Redirect(w, r, "/console/", http.StatusPermanentRedirect)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/console/")
	if name == "" {
		name = "index.html"
	}
	if !fs.ValidPath(name) || path.Clean(name) != name {
		http.NotFound(w, r)
		return
	}
	info, e := fs.Stat(assets, "dist/"+name)
	if e != nil || info.IsDir() || info.Size() > 2<<20 {
		http.NotFound(w, r)
		return
	}
	if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	data, e := assets.ReadFile("dist/" + name)
	if e != nil {
		http.NotFound(w, r)
		return
	}
	// An invalid asset path never falls back to HTML. No directory listing or
	// filesystem access outside the embedded build is possible.
	if strings.HasSuffix(name, ".js") {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	}
	if strings.HasSuffix(name, ".css") {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	if strings.HasSuffix(name, ".html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	http.ServeContent(w, r, name, info.ModTime(), strings.NewReader(string(data)))
}
