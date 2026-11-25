package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Pantek59/dockerstackcontrol/internal/auth"
	"github.com/Pantek59/dockerstackcontrol/internal/config"
	"github.com/Pantek59/dockerstackcontrol/internal/docker"
	"github.com/Pantek59/dockerstackcontrol/internal/stackfiles"
)

// File editing API.
//
// Both endpoints address files by *kind* ("compose" or "env") — a file name
// never travels through the URL. The permission gate for everything here is
// the "edit" action: reading the .env exposes secrets, so it is not granted
// alongside mere viewing.
//
// The editor page renders in editor.html; this file only serves data.

// fileEntryJSON is one entry of GET /api/stacks/{name}/files.
type fileEntryJSON struct {
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	Exists         bool   `json:"exists"`
	Irregular      bool   `json:"irregular,omitempty"`
	Size           int64  `json:"size"`
	Modified       string `json:"modified,omitempty"`
	DefaultContent string `json:"default_content,omitempty"`
}

// filesResponse is the GET /api/stacks/{name}/files body.
type filesResponse struct {
	Stack  string          `json:"stack"`
	HasDir bool            `json:"has_dir"`
	Dir    string          `json:"dir,omitempty"`
	Files  []fileEntryJSON `json:"files"`
}

// contentResponse is the GET body and the PUT response body of one file.
type contentResponse struct {
	Stack          string `json:"stack"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	Exists         bool   `json:"exists"`
	Hash           string `json:"hash"`
	Text           string `json:"text"`
	Modified       string `json:"modified,omitempty"`
	DefaultContent string `json:"default_content,omitempty"`
}

// saveRequest is the PUT body.
type saveRequest struct {
	Content  string `json:"content"`
	BaseHash string `json:"base_hash"`
}

// editGate resolves the stack and enforces "edit" permission for the file
// endpoints, writing the shared 404/403 audit responses. It returns
// (stack, ok).
func (s *Server) editGate(rw http.ResponseWriter, r *http.Request, user auth.User) (config.Stack, bool) {
	stack, access := s.requireStackAccess(rw, r, user, config.ActionEdit)
	return stack, access
}

// validateKind parses and checks the {kind} path value. Unknown kinds are a
// request error before any filesystem access.
func validateKind(rw http.ResponseWriter, kind string) bool {
	if kind == stackfiles.KindCompose || kind == stackfiles.KindEnv {
		return true
	}
	writeJSONError(rw, http.StatusNotFound, "unknown file kind")
	return false
}

// apiFilesList reports the editable files of a stack.
func (s *Server) apiFilesList(rw http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFrom(r.Context())
	if !ok {
		writeJSONError(rw, http.StatusUnauthorized, "no session")
		return
	}
	stack, gated := s.editGate(rw, r, user)
	if !gated {
		return
	}

	start := time.Now()
	resp := filesResponse{Stack: stack.Name, Files: []fileEntryJSON{}, HasDir: stack.Dir != ""}
	entries, ok, err := stackfiles.ListStackFiles(stack.Dir, stack.ComposeFile)
	if err != nil {
		s.audit.FileOp(user.Username, user.Groups, stack.Name, "", "list", "error",
			"", RemoteIP(s.holder.Get(), r), time.Since(start))
		s.logger.Warn("files list failed", "stack", stack.Name, "err", err)
		writeJSONError(rw, http.StatusInternalServerError, "internal error")
		return
	}
	if ok {
		resp.Dir = stack.Dir
		for _, f := range entries {
			e := fileEntryJSON{
				Kind:      f.Kind,
				Name:      f.Name,
				Exists:    f.Exists,
				Irregular: f.Irregular,
				Size:      f.Size,
			}
			if !f.Modified.IsZero() {
				e.Modified = f.Modified.UTC().Format(time.RFC3339)
			}
			resp.Files = append(resp.Files, e)
		}
	}
	writeJSON(rw, http.StatusOK, resp)
}

// apiFileRead returns one file's contents plus the hash the editor must
// attest when saving.
func (s *Server) apiFileRead(rw http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFrom(r.Context())
	if !ok {
		writeJSONError(rw, http.StatusUnauthorized, "no session")
		return
	}
	kind := r.PathValue("kind")
	if !validateKind(rw, kind) {
		return
	}
	stack, gated := s.editGate(rw, r, user)
	if !gated {
		return
	}

	remoteIP := RemoteIP(s.holder.Get(), r)
	start := time.Now()
	file, resolvable, err := stackfiles.ResolveFile(stack.Dir, stack.ComposeFile, kind)
	if !resolvable {
		s.audit.FileOp(user.Username, user.Groups, stack.Name, kind, "read", "denied",
			"no_directory", remoteIP, 0)
		writeJSONError(rw, http.StatusBadRequest, "stack has no configured directory")
		return
	}
	if err != nil {
		s.audit.FileOp(user.Username, user.Groups, stack.Name, kind, "read", "error",
			"", remoteIP, time.Since(start))
		s.logger.Warn("file read failed", "stack", stack.Name, "file", kind, "err", err)
		writeJSONError(rw, http.StatusInternalServerError, "internal error")
		return
	}
	if file.Irregular {
		s.audit.FileOp(user.Username, user.Groups, stack.Name, kind, "read", "denied",
			"not_regular_file", remoteIP, 0)
		writeJSONError(rw, http.StatusConflict, "path is not a regular file")
		return
	}

	resp := contentResponse{
		Stack:  stack.Name,
		Kind:   kind,
		Name:   file.Name,
		Exists: file.Exists,
	}
	if file.Exists {
		content, rerr := stackfiles.Read(file.Path)
		if rerr != nil {
			s.audit.FileOp(user.Username, user.Groups, stack.Name, kind, "read", "error",
				"", remoteIP, time.Since(start))
			s.logger.Warn("file read failed", "stack", stack.Name, "file", kind, "err", rerr)
			writeJSONError(rw, mapFileIOError(rerr), "cannot read file")
			return
		}
		resp.Hash = content.Hash
		resp.Text = content.Text
		resp.Modified = content.Modified.UTC().Format(time.RFC3339)
	} else {
		// Absent file: offer the editor a scaffold to save.
		resp.DefaultContent = defaultContentFor(kind)
	}
	s.audit.FileOp(user.Username, user.Groups, stack.Name, kind, "read", "ok", "", remoteIP, time.Since(start))
	writeJSON(rw, http.StatusOK, resp)
}

// apiFileSave validates and replaces one file's contents. The caller
// attests base_hash (the sha256 of the last read), which is checked after
// the compose validation so that validation cannot be raced with an
// unrelated overwrite.
func (s *Server) apiFileSave(rw http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFrom(r.Context())
	if !ok {
		writeJSONError(rw, http.StatusUnauthorized, "no session")
		return
	}
	kind := r.PathValue("kind")
	if !validateKind(rw, kind) {
		return
	}
	stack, gated := s.editGate(rw, r, user)
	if !gated {
		return
	}

	remoteIP := RemoteIP(s.holder.Get(), r)
	start := time.Now()

	req, err := s.decodeSaveRequest(r)
	if err != nil {
		s.audit.FileOp(user.Username, user.Groups, stack.Name, kind, "save", "denied",
			"bad_request", remoteIP, 0)
		writeJSONError(rw, http.StatusBadRequest, "invalid request body")
		return
	}

	file, resolvable, rerr := stackfiles.ResolveFile(stack.Dir, stack.ComposeFile, kind)
	if !resolvable {
		s.audit.FileOp(user.Username, user.Groups, stack.Name, kind, "save", "denied",
			"no_directory", remoteIP, 0)
		writeJSONError(rw, http.StatusBadRequest, "stack has no configured directory")
		return
	}
	if rerr != nil {
		s.audit.FileOp(user.Username, user.Groups, stack.Name, kind, "save", "error",
			"", remoteIP, time.Since(start))
		s.logger.Warn("file save failed", "stack", stack.Name, "file", kind, "err", rerr)
		writeJSONError(rw, http.StatusInternalServerError, "internal error")
		return
	}
	if file.Irregular {
		s.audit.FileOp(user.Username, user.Groups, stack.Name, kind, "save", "denied",
			"not_regular_file", remoteIP, 0)
		writeJSONError(rw, http.StatusConflict, "path is not a regular file")
		return
	}

	// Serialize against actions and concurrent saves of the same stack.
	lock := s.lockFor(stack.Name)
	if !lock.TryLock() {
		s.audit.FileOp(user.Username, user.Groups, stack.Name, kind, "save", "conflict",
			"in_progress", remoteIP, 0)
		writeJSONError(rw, http.StatusConflict, "an action is already running for this stack")
		return
	}
	defer lock.Unlock()

	// Compose models are schema-checked with `compose config --quiet`
	// (client-side, daemon-less) before anything is written, so a broken
	// file can never reach up -d.
	if kind == stackfiles.KindCompose {
		if verr := s.validateComposeContent(r, stack, file.Name, req.Content); verr != "" {
			s.audit.FileOp(user.Username, user.Groups, stack.Name, kind, "save", "error",
				verr, remoteIP, time.Since(start))
			writeJSONError(rw, http.StatusUnprocessableEntity, "compose validation failed")
			return
		}
	}

	serr := stackfiles.Save(stack.Dir, file.Path, req.Content, req.BaseHash)
	if serr != nil {
		s.audit.FileOp(user.Username, user.Groups, stack.Name, kind, "save", "error",
			sanitizeFileError(serr), remoteIP, time.Since(start))
		s.logger.Warn("file save failed", "stack", stack.Name, "file", kind, "err", serr)
		writeJSONError(rw, mapFileIOError(serr), "cannot save file")
		return
	}

	// Read back what is now on disk: the editor's next change must attest
	// the fresh hash. Failures do not undo the save; the editor just
	// re-reads.
	resp := contentResponse{Stack: stack.Name, Kind: kind, Name: file.Name, Exists: true}
	if saved, rerr := stackfiles.Read(file.Path); rerr == nil {
		resp.Hash = saved.Hash
		resp.Text = saved.Text
		resp.Modified = saved.Modified.UTC().Format(time.RFC3339)
	}
	s.audit.FileOp(user.Username, user.Groups, stack.Name, kind, "save", "ok", "", remoteIP, time.Since(start))
	writeJSON(rw, http.StatusOK, resp)
}

// decodeSaveRequest parses and bounds the PUT body.
func (s *Server) decodeSaveRequest(r *http.Request) (saveRequest, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, stackfiles.MaxFileSize+(64<<10)))
	if err != nil {
		return saveRequest{}, err
	}
	var req saveRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return saveRequest{}, err
	}
	return req, nil
}

// validateComposeContent writes content to a (non-hidden) temporary file
// inside the stack directory and asks the runner to schema-check exactly
// that file, with .env resolution staying inside the stack directory
// (compose derives the project directory from the -f path). It returns an
// audit reason on failure, "" on success, and cleans up the temporary file
// in every case.
func (s *Server) validateComposeContent(r *http.Request, stack config.Stack, composeName, content string) string {
	dir := stack.Dir
	tmp, err := os.CreateTemp(dir, "stackctl-val-*.yml")
	if err != nil {
		s.logger.Warn("compose validation temp file failed", "stack", stack.Name, "err", err)
		return "temp_failure"
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return "temp_failure"
	}
	if err := tmp.Close(); err != nil {
		return "temp_failure"
	}

	spec := docker.StackSpec{
		Project: stack.Project,
		Dir:     dir,
		Compose: filepath.Base(tmpPath),
	}
	verr := s.runner.Validate(r.Context(), spec)
	if verr == nil {
		return ""
	}
	// The validation output (compose schema errors, interpolation
	// complaints) is structural feedback about the edited file itself, not
	// daemon state. The client gets a generic 422; the detail stays in the
	// server log, so the operator can look up why a save was rejected.
	var ce *docker.CommandError
	verb := verr.Error()
	if errors.As(verr, &ce) && ce.Stderr != "" {
		verb = truncateForLog(ce.Stderr, 1024)
	}
	s.logger.Info("compose validation failed",
		"stack", stack.Name, "project", stack.Project, "detail", verb)
	return "compose_validation"
}

// truncateForLog bounds log detail so one bad file cannot bloat the audit
// stream.
func truncateForLog(s string, max int) string {
	if len(s) <= max {
		return strings.TrimRight(s, "\n")
	}
	return s[:max] + "…"
}

// defaultContentFor returns the scaffold the editor offers for an absent
// file.
func defaultContentFor(kind string) string {
	if kind == stackfiles.KindCompose {
		return stackfiles.DefaultComposeContent
	}
	return stackfiles.DefaultEnvContent
}

// mapFileIOError translates stackfiles errors to HTTP status codes.
func mapFileIOError(err error) int {
	switch {
	case errors.Is(err, stackfiles.ErrNotFound), errors.Is(err, os.ErrNotExist):
		return http.StatusNotFound
	case errors.Is(err, stackfiles.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, stackfiles.ErrNotRegular):
		return http.StatusConflict
	case errors.Is(err, stackfiles.ErrTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, stackfiles.ErrBadContent):
		return http.StatusBadRequest
	default:
		return http.StatusBadGateway
	}
}

// sanitizeFileError reduces a stackfiles error to an audit reason string.
func sanitizeFileError(err error) string {
	switch {
	case errors.Is(err, stackfiles.ErrConflict):
		return "conflict"
	case errors.Is(err, stackfiles.ErrNotFound):
		return "not_found"
	case errors.Is(err, stackfiles.ErrNotRegular):
		return "not_regular_file"
	case errors.Is(err, stackfiles.ErrTooLarge):
		return "too_large"
	case errors.Is(err, stackfiles.ErrBadContent):
		return "bad_content"
	default:
		return "io_error"
	}
}
