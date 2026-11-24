package config

import (
	"errors"
	"fmt"
	"sync"
)

// Holder keeps the currently active configuration and swaps it atomically on
// reload. Readers obtain an immutable snapshot via Get; subscriber callbacks
// (for example, the OIDC service) are notified after a successful swap and may
// veto the reload by returning an error (the swap itself is kept, the veto is
// reported back to the caller and logged).
type Holder struct {
	mu       sync.RWMutex
	path     string
	cur      *Config
	onChange []func(*Config) error
}

// NewHolder loads path and returns a holder holding the valid configuration.
func NewHolder(path string) (*Holder, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return &Holder{path: path, cur: cfg}, nil
}

// NewStaticHolder returns a holder around an already valid configuration,
// without a reload path. Intended for tests.
func NewStaticHolder(cfg *Config) *Holder {
	return &Holder{cur: cfg}
}

// Get returns the current configuration snapshot. Treat it as read-only.
func (h *Holder) Get() *Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cur
}

// Path returns the file path this holder reloads from; empty for static holders.
func (h *Holder) Path() string { return h.path }

// OnChange registers a callback invoked after every successful reload. The
// callback must not block for long. If it returns an error, the swap stays in
// effect (callers such as the auth service implement their own fallback) and
// the error is surfaced to the reload caller for logging.
func (h *Holder) OnChange(fn func(*Config) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onChange = append(h.onChange, fn)
}

// Reload re-reads and validates the configuration file. On any validation or
// read error the previous configuration is kept untouched. On success the new
// snapshot is swapped in atomically and subscribers run; errors from
// subscribers are joined and returned after the swap.
func (h *Holder) Reload() error {
	if h.path == "" {
		return errors.New("config: reload requested but no config path is set")
	}
	cfg, err := Load(h.path)
	if err != nil {
		return fmt.Errorf("configuration reload rejected, keeping previous: %w", err)
	}

	h.mu.Lock()
	h.cur = cfg
	subs := make([]func(*Config) error, len(h.onChange))
	copy(subs, h.onChange)
	h.mu.Unlock()

	var errs []error
	for _, fn := range subs {
		if err := fn(cfg); err != nil {
			errs = append(errs, fmt.Errorf("reload subscriber: %w", err))
		}
	}
	return errors.Join(errs...)
}
