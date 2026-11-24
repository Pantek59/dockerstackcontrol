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
)

// writeJSONError writes a small JSON error body for API responses.
func writeJSONError(rw http.ResponseWriter, status int, msg string) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(status)
	_, _ = fmt.Fprintf(rw, `{"error":%q}`, msg)
}

// dashboard is the authenticated start page. With the API the GUI is fed by
// JSON; the actual markup lives in the embedded templates.
func (s *Server) dashboard(rw http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFrom(r.Context())
	if !ok {
		http.Error(rw, "authentication required", http.StatusUnauthorized)
		return
	}
	// TODO(M6): render the embedded layout/dashboard templates.
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(rw, "<!doctype html><html><body><h1>Stack Control</h1><p>Signed in as %s.</p></body></html>", user.Username)
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
				AllowedActions: authz.AllowedActions(cfg, user.Username, user.Groups, st.Name),
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

// writeJSON marshals v and writes it with the status code. Encoding these
// plain structs cannot fail; a write error (client gone) is not actionable.
func writeJSON(rw http.ResponseWriter, status int, v any) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(v)
}

// apiAction performs start/stop/restart on one stack. This is the security
// entry point for mutating requests; the order checks are:
//
//  1. session + CSRF (middleware, before us),
//  2. stack known and visible to the user (404 otherwise — unknown and
//     invisible stacks are indistinguishable on purpose),
//  3. action allowed for this user (403 otherwise),
//  4. per-stack lock (409 when an action is already running),
//  5. docker compose action (502/504 on failure, never leaking output).
//
// Every attempt — granted or not — produces one audit line.
func (s *Server) apiAction(rw http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFrom(r.Context())
	if !ok {
		writeJSONError(rw, http.StatusUnauthorized, "no session")
		return
	}
	cfg := s.holder.Get()
	name := r.PathValue("name")
	actionStr := r.PathValue("action")

	remoteIP := RemoteIP(cfg, r)

	// (1) Stack known? (2) Visible? Unknown and invisible share 404.
	stack, known := cfg.Stack(name)
	if !known || !authz.IsVisible(cfg, user.Username, user.Groups, name) {
		project := name
		if known {
			project = stack.Project
		}
		s.audit.StackAction(user.Username, user.Groups, name, project, actionStr,
			"denied", "unknown_or_invisible", remoteIP, 0)
		writeJSONError(rw, http.StatusNotFound, "not found")
		return
	}

	// (3) Action allowed?
	if !authz.Can(cfg, user.Username, user.Groups, name, actionStr) {
		s.audit.StackAction(user.Username, user.Groups, name, stack.Project, actionStr,
			"denied", "no_permission", remoteIP, 0)
		writeJSONError(rw, http.StatusForbidden, "action not allowed")
		return
	}
	action, _ := docker.ParseAction(actionStr) // Can above guarantees validity

	// (4) Serialize: at most one running action per stack; concurrent calls
	// get 409 instead of queuing behind a potentially long operation.
	lock := s.lockFor(name)
	if !lock.TryLock() {
		s.audit.StackAction(user.Username, user.Groups, name, stack.Project, actionStr,
			"conflict", "in_progress", remoteIP, 0)
		writeJSONError(rw, http.StatusConflict, "an action is already running for this stack")
		return
	}
	defer lock.Unlock()

	// (5) Execute.
	start := time.Now()
	err := s.runner.Do(r.Context(), stack.Project, action)
	duration := time.Since(start)

	result, status := classifyDockerActionError(err)
	s.audit.StackAction(user.Username, user.Groups, name, stack.Project, actionStr,
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
		AllowedActions: authz.AllowedActions(cfg, user.Username, user.Groups, name),
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
