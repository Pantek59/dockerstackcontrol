package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Pantek59/dockerstackcontrol/internal/auth"
	"github.com/Pantek59/dockerstackcontrol/internal/authz"
	"github.com/Pantek59/dockerstackcontrol/internal/config"
	"github.com/Pantek59/dockerstackcontrol/internal/docker"
	"github.com/Pantek59/dockerstackcontrol/internal/stackfiles"
)

// writeJSONError writes a small JSON error body for API responses.
func writeJSONError(rw http.ResponseWriter, status int, msg string) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(status)
	_, _ = fmt.Fprintf(rw, `{"error":%q}`, msg)
}

// dashboard renders the authenticated start page; the stack list is filled
// in by app.js from the JSON API.
func (s *Server) dashboard(rw http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFrom(r.Context())
	if !ok {
		http.Error(rw, "authentication required", http.StatusUnauthorized)
		return
	}
	s.renderPage(rw, "dashboard.html", PageData{
		Username:  user.Username,
		CSRFToken: user.CSRFToken,
	}, http.StatusOK)
}

// stackJSON is one entry of GET /api/stacks.
type stackJSON struct {
	Name           string           `json:"name"`
	Label          string           `json:"label"`
	State          string           `json:"state"`
	Services       []docker.Service `json:"services"`
	AllowedActions []string         `json:"allowed_actions"`
}

// stacksResponse is the GET /api/stacks body.
type stacksResponse struct {
	User      string      `json:"user"`
	CSRFToken string      `json:"csrf_token"`
	Stacks    []stackJSON `json:"stacks"`
}

// apiStacks lists the stacks visible to the user with their live status.
// Docker status errors degrade to state "unknown" per stack so one broken
// command cannot blank the whole listing; they are logged server-side.
func (s *Server) apiStacks(rw http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFrom(r.Context())
	if !ok { // unreachable behind RequireSession, kept defensive
		writeJSONError(rw, http.StatusUnauthorized, "no session")
		return
	}
	cfg := s.holder.Get()

	visible := authz.VisibleStacks(cfg, user.Username, user.Groups)
	results := make([]stackJSON, len(visible))
	var wg sync.WaitGroup
	for i, st := range visible {
		wg.Add(1)
		go func(i int, st config.Stack) {
			defer wg.Done()
			entry := stackJSON{
				Name:           st.Name,
				Label:          st.Label,
				State:          docker.StateUnknown,
				Services:       []docker.Service{},
				AllowedActions: visibleAllowedActions(cfg, user, st),
			}
			status, err := s.runner.Status(r.Context(), st.Project)
			if err != nil {
				s.logger.Warn("docker status failed",
					"stack", st.Name, "project", st.Project, "err", err)
			} else {
				entry.State = status.State
				entry.Services = status.Services
			}
			results[i] = entry
		}(i, st)
	}
	wg.Wait()

	writeJSON(rw, http.StatusOK, stacksResponse{
		User:      user.Username,
		CSRFToken: user.CSRFToken,
		Stacks:    results,
	})
}

// requireStackAccess resolves the named stack for the user and writes the
// shared 404/403 responses (with their audit lines) when access is not
// granted. It returns (stack, "known-and-visible", "action-allowed").
func (s *Server) requireStackAccess(rw http.ResponseWriter, r *http.Request, user auth.User, actionStr string) (config.Stack, bool) {
	cfg := s.holder.Get()
	name := r.PathValue("name")
	remoteIP := RemoteIP(cfg, r)

	stack, known := cfg.Stack(name)
	if !known || !authz.IsVisible(cfg, user.Username, user.Groups, name) {
		project := name
		if known {
			project = stack.Project
		}
		s.audit.StackAction(user.Username, user.Groups, name, project, actionStr,
			"denied", "unknown_or_invisible", remoteIP, 0)
		writeJSONError(rw, http.StatusNotFound, "not found")
		return config.Stack{}, false
	}
	if !authz.Can(cfg, user.Username, user.Groups, name, actionStr) {
		s.audit.StackAction(user.Username, user.Groups, name, stack.Project, actionStr,
			"denied", "no_permission", remoteIP, 0)
		writeJSONError(rw, http.StatusForbidden, "action not allowed")
		return config.Stack{}, false
	}
	return stack, true
}

// visibleAllowedActions returns the user's allowed actions on the stack with
// the file-backed actions (pull, up, edit) removed when the stack does not
// declare a directory: those buttons must not render, and the endpoints must
// not pretend they work, without a compose model on disk.
func visibleAllowedActions(cfg *config.Config, user auth.User, stack config.Stack) []string {
	allowed := authz.AllowedActions(cfg, user.Username, user.Groups, stack.Name)
	if stack.Dir != "" {
		return allowed
	}
	out := make([]string, 0, len(allowed))
	for _, a := range allowed {
		if config.ActionRequiresFiles(a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// writeJSON marshals v and writes it with the status code. Encoding these
// plain structs cannot fail; a write error (client gone) is not actionable.
func writeJSON(rw http.ResponseWriter, status int, v any) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(v)
}

// apiAction performs start/stop/restart/pull/up on one stack. This is the
// security entry point for mutating requests; the order checks are:
//
//  1. session + CSRF (middleware, before us),
//  2. stack known and visible to the user (404 otherwise — unknown and
//     invisible stacks are indistinguishable on purpose),
//  3. action allowed for this user (403 otherwise),
//  4. per-stack lock (409 when an action is already running),
//  5. docker compose action (502/504 on failure, never leaking output).
//
// The file-backed actions pull and up additionally require the stack to
// declare a directory with a resolvable main compose file; 400 otherwise
// (audited as "no_directory"/"compose_unresolved"). That precondition is
// checked again here even though the UI already hides the buttons
// (defense in depth: the API is the enforcement point).
//
// Every attempt — granted or not — produces one audit line.
func (s *Server) apiAction(rw http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFrom(r.Context())
	if !ok {
		writeJSONError(rw, http.StatusUnauthorized, "no session")
		return
	}
	cfg := s.holder.Get()
	actionStr := r.PathValue("action")
	remoteIP := RemoteIP(cfg, r)

	// (1) Stack known? (2) Visible? (3) Action allowed? Unknown and
	// invisible share 404; disallowed actions get 403.
	stack, access := s.requireStackAccess(rw, r, user, actionStr)
	if !access {
		return
	}
	action, valid := docker.ParseAction(actionStr)
	if !valid {
		// authz.Can only accepts actions in the config enum; "edit" is one
		// of those but has no action endpoint (it is the editor page).
		s.audit.StackAction(user.Username, user.Groups, stack.Name, stack.Project, actionStr,
			"denied", "no_such_endpoint", remoteIP, 0)
		writeJSONError(rw, http.StatusNotFound, "not found")
		return
	}

	// (4) Serialize: at most one running action per stack; concurrent calls
	// get 409 instead of queuing behind a potentially long operation.
	lock := s.lockFor(stack.Name)
	if !lock.TryLock() {
		s.audit.StackAction(user.Username, user.Groups, stack.Name, stack.Project, actionStr,
			"conflict", "in_progress", remoteIP, 0)
		writeJSONError(rw, http.StatusConflict, "an action is already running for this stack")
		return
	}
	defer lock.Unlock()

	// (5) Execute. File-backed actions resolve the compose model first.
	spec := docker.StackSpec{Project: stack.Project}
	if actionRequiresFile(action) {
		composeFile, ferr := s.composeFileFor(stack)
		if ferr != "" {
			s.audit.StackAction(user.Username, user.Groups, stack.Name, stack.Project, actionStr,
				"denied", ferr, remoteIP, 0)
			writeJSONError(rw, http.StatusBadRequest, "stack has no usable compose file (is \"dir\" configured?)")
			return
		}
		spec.Dir, spec.Compose = stack.Dir, composeFile
	}

	start := time.Now()
	err := s.runner.Do(r.Context(), spec, action)
	duration := time.Since(start)

	result, status := classifyDockerActionError(err)
	s.audit.StackAction(user.Username, user.Groups, stack.Name, stack.Project, actionStr,
		result, "", remoteIP, duration)
	if err != nil {
		// Sanitized: command output never reaches the client.
		writeJSONError(rw, status, err.Error())
		return
	}

	// Report the stack's new status; failures here keep the action's success
	// (HTTP 200) but degrade the state to "unknown".
	entry := stackJSON{
		Name:           stack.Name,
		Label:          stack.Label,
		State:          docker.StateUnknown,
		Services:       []docker.Service{},
		AllowedActions: visibleAllowedActions(cfg, user, stack),
	}
	status2, serr := s.runner.Status(r.Context(), stack.Project)
	if serr != nil {
		s.logger.Warn("docker status after action failed",
			"stack", stack.Name, "project", stack.Project, "err", serr)
	} else {
		entry.State = status2.State
		entry.Services = status2.Services
	}
	writeJSON(rw, http.StatusOK, entry)
}

// actionRequiresFile mirrors docker's requiresFile without leaking the enum
// into a public wrapper: the server knows which actions are file-backed.
func actionRequiresFile(action docker.Action) bool {
	return action == docker.ActionPull || action == docker.ActionUp
}

// composeFileFor resolves the absolute path of the stack's main compose
// model. It returns the path or a (sanitized, auditable) reason for the
// failure.
func (s *Server) composeFileFor(stack config.Stack) (string, string) {
	path, ok, err := stackfiles.ResolveCompose(stack.Dir, stack.ComposeFile)
	if !ok {
		return "", "no_directory"
	}
	if err != nil {
		s.logger.Warn("compose file resolution failed",
			"stack", stack.Name, "project", stack.Project, "err", err)
		return "", "compose_unresolved"
	}
	return path, ""
}

// classifyDockerActionError maps runner errors to audit results and HTTP
// status codes.
func classifyDockerActionError(err error) (result string, status int) {
	switch {
	case err == nil:
		return "ok", http.StatusOK
	case errors.Is(err, docker.ErrTimeout):
		return "timeout", http.StatusGatewayTimeout
	default:
		return "error", http.StatusBadGateway
	}
}
