package server

import (
	"net/http"
	"time"

	"github.com/Pantek59/dockerstackcontrol/internal/auth"
	"github.com/Pantek59/dockerstackcontrol/internal/authz"
	"github.com/Pantek59/dockerstackcontrol/internal/config"
	"github.com/Pantek59/dockerstackcontrol/internal/stackfiles"
)

// EditorData drives editor.html. The layout consumes Username and
// CSRFToken; the content template consumes the rest.
type EditorData struct {
	Username   string
	CSRFToken  string
	StackName  string
	StackLabel string
	Compose    EditorFileView
	Env        EditorFileView
}

// EditorFileView is one editable file's editor state.
type EditorFileView struct {
	Kind   string
	Name   string
	Exists bool
	// Irregular: the path exists but is not a regular file; no editing.
	Irregular bool
	// Text is the current content, or the scaffold for an absent file.
	Text string
	// Hash is the save-attestation of Text: empty means "the file does not
	// exist yet" (the editor then saves with an empty base hash).
	Hash string
	// Modified is a human-readable UTC timestamp, when the file exists.
	Modified string
	Size     int64
}

// editorPage renders the stack file editor (compose model and .env). All
// authorization decisions live here and in the API below it; the page is a
// convenience only.
func (s *Server) editorPage(rw http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFrom(r.Context())
	if !ok { // RequireSession(false) already redirected; defensive
		http.Redirect(rw, r, "/login", http.StatusFound)
		return
	}
	cfg := s.holder.Get()
	name := r.PathValue("name")

	stack, known := cfg.Stack(name)
	if !known || !authz.IsVisible(cfg, user.Username, user.Groups, name) {
		// Unknown and invisible stacks are indistinguishable, as everywhere.
		s.renderErrorPage(rw, r, http.StatusNotFound, "page not found")
		return
	}
	if !authz.Can(cfg, user.Username, user.Groups, name, config.ActionEdit) {
		s.renderErrorPage(rw, r, http.StatusForbidden, "editing this stack is not allowed for you")
		return
	}
	if stack.Dir == "" {
		s.renderErrorPage(rw, r, http.StatusNotFound, "this stack has no configured directory")
		return
	}

	data := EditorData{
		Username:   user.Username,
		CSRFToken:  user.CSRFToken,
		StackName:  stack.Name,
		StackLabel: stack.Label,
	}
	if fill, ok := s.editorFileView(stack, stackfiles.KindCompose); ok {
		data.Compose = fill
	} else {
		s.renderErrorPage(rw, r, http.StatusInternalServerError, "cannot read compose file")
		return
	}
	if fill, ok := s.editorFileView(stack, stackfiles.KindEnv); ok {
		data.Env = fill
	} else {
		s.renderErrorPage(rw, r, http.StatusInternalServerError, "cannot read .env file")
		return
	}

	s.renderPage(rw, "editor.html", data, http.StatusOK)
}

// editorFileView reads one file for the initial editor render. A read
// failure yields ok=false; the caller renders a server error page — better
// a hard error than an editor showing stale state.
func (s *Server) editorFileView(stack config.Stack, kind string) (EditorFileView, bool) {
	file, resolvable, err := stackfiles.ResolveFile(stack.Dir, stack.ComposeFile, kind)
	if !resolvable {
		return EditorFileView{}, false
	}
	if err != nil {
		s.logger.Warn("editor file resolution failed",
			"stack", stack.Name, "file", kind, "err", err)
		return EditorFileView{}, false
	}
	if file.Irregular {
		return EditorFileView{
			Kind:      kind,
			Name:      file.Name,
			Irregular: true,
		}, true
	}

	view := EditorFileView{
		Kind:   kind,
		Name:   file.Name,
		Exists: file.Exists,
		Size:   file.Size,
	}
	if !file.Modified.IsZero() {
		view.Modified = file.Modified.UTC().Format(time.RFC1123)
	}
	if file.Exists {
		content, rerr := stackfiles.Read(file.Path)
		if rerr != nil {
			s.logger.Warn("editor file read failed",
				"stack", stack.Name, "file", kind, "err", rerr)
			return EditorFileView{}, false
		}
		view.Text = content.Text
		view.Hash = content.Hash
	} else {
		view.Text = defaultContentFor(kind)
		// view.Hash stays "": the editor saves with an empty base hash to
		// create the file.
	}
	return view, true
}
