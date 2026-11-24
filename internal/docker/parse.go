package docker

import (
	"encoding/json"
	"fmt"
)

// composePSItem mirrors one JSON object emitted by
// `docker compose ps -a --format json`. Compose prints either a JSON array of
// these objects or one object per line (observed on Compose 5.8.0); the older
// one-per-line form is also accepted, per the plan.
type composePSItem struct {
	Name    string `json:"Name"`
	Names   string `json:"Names"`
	Service string `json:"Service"`
	State   string `json:"State"`
	Health  string `json:"Health"`
	Project string `json:"Project"`
}

// ParsePS parses `docker compose ps -a --format json` output in both the JSON
// array format and the one-object-per-line format. An empty (or whitespace
// only) input yields no items; that means the project has no containers.
func ParsePS(stdout []byte) ([]composePSItem, error) {
	trimmed := trimWhitespace(stdout)
	if len(trimmed) == 0 {
		return nil, nil
	}

	if trimmed[0] == '[' {
		var items []composePSItem
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, fmt.Errorf("parse compose ps array output: %w", err)
		}
		if items == nil {
			items = []composePSItem{}
		}
		return items, nil
	}

	var items []composePSItem
	for _, line := range splitLines(trimmed) {
		if len(line) == 0 {
			continue
		}
		var it composePSItem
		if err := json.Unmarshal(line, &it); err != nil {
			return nil, fmt.Errorf("parse compose ps line output: %w", err)
		}
		items = append(items, it)
	}
	return items, nil
}

// serviceName picks the compose service name, falling back to the container
// name when Service is missing (some compose versions omit it).
func (it composePSItem) serviceName() string {
	if it.Service != "" {
		return it.Service
	}
	if it.Name != "" {
		return it.Name
	}
	return it.Names
}

// ParseStatus converts ps output into a StackStatus:
//   - no containers: StateNotFound,
//   - all services running: StateRunning,
//   - no service running: StateStopped,
//   - mixed: StatePartial.
//
// The overall state is derived purely from the running count; each service
// keeps its raw container state for display.
func ParseStatus(stdout []byte) (StackStatus, error) {
	items, err := ParsePS(stdout)
	if err != nil {
		return StackStatus{State: StateUnknown}, err
	}

	services := make([]Service, 0, len(items))
	for _, it := range items {
		name := it.serviceName()
		if name == "" {
			continue
		}
		state := it.State
		if state == "" {
			state = StateUnknown
		}
		services = append(services, Service{Name: name, State: state})
	}
	return StackStatus{State: DeriveState(services), Services: services}, nil
}

// DeriveState aggregates per-service container states into a stack state.
func DeriveState(services []Service) string {
	if len(services) == 0 {
		return StateNotFound
	}
	running := 0
	for _, s := range services {
		if s.State == ServiceRunning {
			running++
		}
	}
	switch {
	case running == len(services):
		return StateRunning
	case running == 0:
		return StateStopped
	default:
		return StatePartial
	}
}

func trimWhitespace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func splitLines(b []byte) [][]byte {
	var lines [][]byte
	current := make([]byte, 0, 128)
	for _, c := range b {
		switch c {
		case '\r':
		case '\n':
			lines = append(lines, current)
			current = make([]byte, 0, 128)
		default:
			current = append(current, c)
		}
	}
	lines = append(lines, current)
	return lines
}
