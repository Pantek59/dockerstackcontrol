package server

import (
	"html/template"
	"io/fs"
	"net/http"

	"github.com/Pantek59/dockerstackcontrol/internal/auth"
	"github.com/Pantek59/dockerstackcontrol/web"
)

// PageData carries everything the templates need. The dashboard ignores
// Status/Message; the error page uses them. html/template escapes all of
// these to the right context automatically.
type PageData struct {
	Username  string
	CSRFToken string
	Status    int
	Message   string
}

// parseTemplates builds one template set per page: layout.html is shared and
// each page file contributes its own "content" definition.
func parseTemplates() (map[string]*template.Template, error) {
	base := template.New("layout.html")
	base, err := base.ParseFS(web.TemplatesFS, "templates/layout.html")
	if err != nil {
		return nil, err
	}
	pages := []string{"dashboard.html", "error.html"}
	out := make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		clone, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := clone.ParseFS(web.TemplatesFS, "templates/"+page); err != nil {
			return nil, err
		}
		out[page] = clone
	}
	return out, nil
}

// staticHandler builds the /static/ file server over the embedded assets.
// Assets are revalidated each request (no-cache) so upgrades take effect
// without a fixed filename versioning scheme.
func staticHandler() (http.Handler, error) {
	root, err := fs.Sub(web.StaticFS, "static")
	if err != nil {
		return nil, err
	}
	files := http.StripPrefix("/static/", http.FileServer(http.FS(root)))
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(rw, r)
	}), nil
}

// renderPage executes the named page wrapped in the layout with the given
// HTTP status.
func (s *Server) renderPage(rw http.ResponseWriter, page string, data PageData, status int) {
	tpl, ok := s.templates[page]
	if !ok {
		http.Error(rw, "template missing", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(status)
	if err := tpl.ExecuteTemplate(rw, "layout.html", data); err != nil {
		// Headers may already be written; log server-side only.
		s.logger.Error("template execution failed", "page", page, "err", err)
	}
}

// renderErrorPage renders the HTML error page for non-API responses.
func (s *Server) renderErrorPage(rw http.ResponseWriter, r *http.Request, status int, msg string) {
	user, _ := auth.UserFrom(r.Context())
	s.renderPage(rw, "error.html", PageData{
		Username:  user.Username,
		CSRFToken: "", // an error page never offers a CSRF token
		Status:    status,
		Message:   msg,
	}, status)
}
