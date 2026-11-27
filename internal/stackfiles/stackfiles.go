// Package stackfiles reads and writes the files that define a stack (its
// main compose file and .env) with the safety properties the rest of
// stackctl relies on:
//
//   - Files are addressed by the caller as an absolute directory plus a
//     plain file name; this package joins and re-checks both halves and
//     refuses anything else.
//   - Symlinks are rejected: an attacker who can create a symlink inside a
//     stack directory must not be able to make stackctl read or write
//     elsewhere.
//   - Every read/write is bounded in size and checked to be UTF-8 text
//     without NUL bytes.
//   - Saves are guarded by optimistic concurrency (sha256 of the version the
//     editor last saw), rotate dated backups, and replace the target by an
//     atomically renamed write inside the same directory.
//
// The package does no authorization; callers check permissions first. It
// performs no exec and does not talk to the daemon.
package stackfiles

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf8"
)

// MaxFileSize bounds one read and one write, in bytes. Compose files for
// real-world stacks are a few KiB; half a MiB is generous headroom while
// limiting the impact of accidental and hostile writes alike.
const MaxFileSize = 512 << 10

// backupKeep is how many timestamped backups per file are kept before the
// oldest is pruned.
const backupKeep = 10

// backupDirName is the (hidden) subdirectory of the stack directory that
// receives backups, mode 0700. It lives inside the stack directory — not in
// a global path — so that the deployment only has to mount the stack
// directories themselves.
const backupDirName = ".stackctl-backups"

// tempPrefix marks stackctl's in-flight writes inside the stack directory.
const tempPrefix = ".stackctl-tmp-"

// Sentinel errors, mapped to HTTP statuses by the server.
var (
	// ErrConflict: the file changed since the caller last read it (sha256
	// mismatch, or a hash was attested for a file that does not exist).
	ErrConflict = errors.New("file changed since it was last read")
	// ErrNotFound: the addressed file (or its directory) does not exist.
	ErrNotFound = errors.New("file not found")
	// ErrTooLarge: read or write exceeds MaxFileSize.
	ErrTooLarge = errors.New("file too large")
	// ErrNotRegular: the addressed path is not a regular file (directories,
	// devices and — deliberately — symlinks are refused).
	ErrNotRegular = errors.New("path is not a regular file")
	// ErrBadContent: content is not plain UTF-8 text (NUL or invalid UTF-8).
	ErrBadContent = errors.New("content is not valid UTF-8 text")
)

// File kinds. Files are addressed by kind, never by a caller-supplied file
// name: "compose" is the stack's main compose model, "env" its .env file.
const (
	KindCompose = "compose"
	KindEnv     = "env"
)

// MainComposeFile is the preferred main compose file name.
const MainComposeFile = "docker-compose.yml"

// EnvFileName is the name of the environment file of a stack, as compose
// reads it from the project directory.
const EnvFileName = ".env"

// composeFileCandidates is the detection order for the main compose file
// when the configuration does not pin compose_file.
var composeFileCandidates = []string{
	MainComposeFile,
	"docker-compose.yaml",
	"compose.yaml",
	"compose.yml",
}

// BackupDir returns the backup subdirectory path of a stack directory.
func BackupDir(dir string) string { return filepath.Join(dir, backupDirName) }

// File describes one addressable file of a stack.
type File struct {
	Kind string `json:"kind"`
	// Name is the file's base name as it appears on disk.
	Name string `json:"name"`
	// Path is the absolute on-disk path (server-side only; never serialized
	// to clients — the host directory layout is not their business).
	Path string `json:"-"`
	// Exists reports whether a regular file is present and read/writable.
	Exists bool `json:"exists"`
	// Irregular reports whether a non-regular entry (symlink, directory,
	// device) occupies the file's path; such entries are never read or
	// written, so Exists stays false.
	Irregular bool `json:"irregular,omitempty"`
	// Size and Modified are populated when the file exists.
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

// FileEntry is the JSON shape of the files listing endpoint.
type FileEntry struct {
	File
	// DefaultContent is non-empty when the file does not exist yet and the
	// editor may create it.
	DefaultContent string `json:"default_content,omitempty"`
}

// resolveName returns the on-disk name of the addressed kind inside dir,
// applying the detection order for the main compose file. An absent file is
// a valid result (the name is the conventional default the editor would
// create).
func resolveName(dir, override, kind string) string {
	if kind == KindEnv {
		return EnvFileName
	}
	if override != "" {
		return override
	}
	if detected := detectComposeFile(dir); detected != "" {
		return detected
	}
	return MainComposeFile
}

// ResolveFile returns the File description for kind ("compose" or "env") in
// the stack directory. dir may be empty, which yields ok=false: the stack
// has no configured directory, so file operations are unavailable for it.
// composeOverride pins the compose file name; when empty the standard
// detection order applies.
func ResolveFile(dir, composeOverride, kind string) (File, bool, error) {
	switch kind {
	case KindCompose, KindEnv:
	default:
		return File{}, false, fmt.Errorf("unknown file kind %q", kind)
	}
	if dir == "" {
		return File{}, false, nil
	}

	name := resolveName(dir, composeOverride, kind)
	path, err := joinPath(dir, name)
	if err != nil {
		return File{}, false, err
	}
	f := File{Kind: kind, Name: name, Path: path}

	info, lerr := os.Lstat(path)
	switch {
	case errors.Is(lerr, os.ErrNotExist):
		return f, true, nil // absent is a valid state: the editor can create it
	case lerr != nil:
		return File{}, false, lerr
	}
	if !info.Mode().IsRegular() {
		// Addressable but unusable: occupied by something that is not a
		// regular file (deliberately including symlinks).
		f.Irregular = true
		return f, true, nil
	}
	f.Exists = true
	f.Size = info.Size()
	f.Modified = info.ModTime()
	return f, true, nil
}

// ResolveCompose returns the absolute path of the stack's main compose
// model (dir plus detected or overridden file name) for file-backed docker
// compose commands. ok=false when the stack has no configured directory.
// A configured directory whose model is missing or not a regular file
// yields ErrNotFound.
func ResolveCompose(dir, composeOverride string) (path string, ok bool, err error) {
	if dir == "" {
		return "", false, nil
	}
	name := resolveName(dir, composeOverride, KindCompose)
	joined, jerr := joinPath(dir, name)
	if jerr != nil {
		return "", false, jerr
	}
	info, lerr := os.Lstat(joined)
	if lerr != nil || !info.Mode().IsRegular() {
		return "", true, ErrNotFound
	}
	return joined, true, nil
}

// ListStackFiles returns the addressable files for a stack directory in a
// fixed order (compose, then env). Returns nil,false when dir is empty.
func ListStackFiles(dir, composeOverride string) ([]File, bool, error) {
	if dir == "" {
		return nil, false, nil
	}
	var out []File
	for _, kind := range []string{KindCompose, KindEnv} {
		f, ok, err := ResolveFile(dir, composeOverride, kind)
		if err != nil {
			return nil, false, err
		}
		if ok {
			out = append(out, f)
		}
	}
	return out, true, nil
}

// detectComposeFile returns the first regular (non-symlink!) main compose
// file present in dir.
func detectComposeFile(dir string) string {
	for _, candidate := range composeFileCandidates {
		info, err := os.Lstat(filepath.Join(dir, candidate))
		if err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}

// joinPath validates the directory and the file name and returns the joined
// absolute path. dir must be a clean absolute path; name must be a plain
// name that stays inside dir.
func joinPath(dir, name string) (string, error) {
	if dir == "" {
		return "", errors.New("stack has no configured directory")
	}
	cleaned := filepath.Clean(dir)
	if !filepath.IsAbs(cleaned) || cleaned != dir {
		return "", fmt.Errorf("stack directory %q must be a clean absolute path", dir)
	}
	if !validName(name) {
		return "", fmt.Errorf("invalid file name %q", name)
	}
	return filepath.Join(cleaned, name), nil
}

// validName mirrors internal/config's compose_file validation (plain file
// name) plus the special .env name. Duplication, as with the project name
// regexp in the docker package, keeps this package free of dependency
// cycles.
func validName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	if name == "." || name == ".." {
		return false
	}
	// A leading dot is only allowed for the exact env file name: hidden dot
	// files (..bashrc, .ssh) are never legitimate targets.
	if name[0] == '.' && name != EnvFileName {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// Content is one snapshot of a file's text plus the hash identifying it for
// optimistic concurrency. Hash is sha256 of the exact on-disk bytes; an
// editor that saves must attest it.
type Content struct {
	Text     string    `json:"text"`
	Hash     string    `json:"hash"`
	Modified time.Time `json:"modified"`
}

// hashOf computes the sha256 that guards a content snapshot.
func hashOf(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// openFile opens path read-only without following a final symlink and
// verifies it is a regular file (guards against a path swapped between
// Lstat and open).
func openFile(path string) (*os.File, os.FileInfo, error) {
	// Linux-only: the codebase already relies on Linux syscalls (process
	// groups, docker.sock), and O_NOFOLLOW is the symlink guard here.
	f, err := openGuarded(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, mapOpenErr(err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, ErrNotRegular
	}
	return f, fi, nil
}

// mapOpenErr translates open errors to the sentinel errors.
func mapOpenErr(err error) error {
	// O_NOFOLLOW refuses a trailing symlink (ELOOP on Unix); guard-specific
	// errors map to the "not a regular file" sentinel.
	err = mapGuardedErr(err)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return ErrNotFound
	case errors.Is(err, syscall.EISDIR):
		return ErrNotRegular
	default:
		return err
	}
}

// readRaw reads the full current content, bounded. Used by Read and as the
// source for backups; also returns the open-time file info.
func readRaw(path string) ([]byte, os.FileInfo, error) {
	f, fi, err := openFile(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > MaxFileSize {
		return nil, nil, ErrTooLarge
	}
	return raw, fi, nil
}

// checkText converts raw bytes to a Go string, refusing NUL bytes and
// invalid UTF-8.
func checkText(raw []byte) (string, error) {
	for _, b := range raw {
		if b == 0 {
			return "", ErrBadContent
		}
	}
	if !utf8.Valid(raw) {
		return "", ErrBadContent
	}
	return string(raw), nil
}

// Read reads the regular file at path: bounded to MaxFileSize, UTF-8 text
// only. Returns ErrNotFound, ErrNotRegular, ErrTooLarge or ErrBadContent on
// refusal.
func Read(path string) (Content, error) {
	raw, fi, err := readRaw(path)
	if err != nil {
		return Content{}, err
	}
	text, err := checkText(raw)
	if err != nil {
		return Content{}, err
	}
	return Content{
		Text:     text,
		Hash:     hashOf(text),
		Modified: fi.ModTime(),
	}, nil
}

// Save replaces the file at path with content, provided the caller attests
// baseHash — the sha256 handed out by the last Read of this file. Saving an
// absent file requires baseHash == "" (and fails when the file appeared in
// the meantime, so concurrent creations cannot clobber each other).
//
// Steps: bound + text checks; conflict check against the current content;
// backup of current content; atomic write via temp file + rename in the
// same directory.
func Save(dir, path, content, baseHash string) error {
	if len(content) > MaxFileSize {
		return ErrTooLarge
	}
	if _, err := checkText([]byte(content)); err != nil {
		return err
	}
	if want, err := joinPath(dir, filepath.Base(path)); err != nil || want != path {
		return fmt.Errorf("path %q is not a valid target inside %q", path, dir)
	}

	current, _, lerr := readRaw(path)
	switch {
	case errors.Is(lerr, ErrNotFound):
		current = nil
		if baseHash != "" {
			return ErrConflict // attests a version that no longer exists
		}
	case lerr != nil:
		return lerr // ErrNotRegular, ErrTooLarge, IO error: refuse the save
	}
	if current != nil {
		if baseHash == "" {
			return ErrConflict
		}
		if hashOf(string(current)) != baseHash {
			return ErrConflict
		}
		if err := backup(dir, path, current); err != nil {
			return err
		}
	}

	mode := saveMode(path, current)
	tmp, err := writeTemp(path, []byte(content), mode)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stack directory %q is missing (mounted?): %w", dir, os.ErrNotExist)
		}
		return err
	}
	// os.Rename never follows symlinks and atomically replaces the entry;
	// a concurrent writer of the same path is serialized by the caller's
	// per-stack lock.
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(dir)
	return nil
}

// saveMode returns the mode for the saved file: the current file's mode when
// one exists (and keeps owner-write), otherwise 0600 for .env (secrets) and
// 0644 for everything else (e.g. compose files).
func saveMode(path string, current []byte) os.FileMode {
	if current != nil {
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			mode := info.Mode().Perm()
			if mode&0o200 != 0 {
				return mode
			}
		}
	}
	if filepath.Base(path) == EnvFileName {
		return 0o600
	}
	return 0o644
}

// writeTemp creates .stackctl-tmp-<name> in the same directory with the
// given mode, writes and fsyncs it, returning its path for the rename.
func writeTemp(path string, content []byte, mode os.FileMode) (string, error) {
	tmpPath := filepath.Join(filepath.Dir(path), tempPrefix+filepath.Base(path))
	// O_EXCL refuses an existing temp (never clobber, never follow symlinks
	// thanks to the O_NOFOLLOW guard on the leaf).
	fd, err := openGuarded(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// A crashed earlier run left its temp behind: clean and retry
			// once (the temp is exclusively ours by name).
			_ = os.Remove(tmpPath)
			fd, err = openGuarded(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		}
		if err != nil {
			return "", mapOpenErr(err)
		}
	}
	// The mode argument is subject to umask; enforce it explicitly.
	if err := os.Chmod(tmpPath, mode); err != nil {
		_ = fd.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if _, err := fd.Write(content); err != nil {
		_ = fd.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := fd.Sync(); err != nil {
		_ = fd.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := fd.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}

// backup stores current under <dir>/.stackctl-backups/<unix-nano>-<name> and
// prunes backups of the same file beyond the newest backupKeep.
func backup(dir, path string, current []byte) error {
	backupDir := BackupDir(dir)
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	name := fmt.Sprintf("%019d-%s", time.Now().UnixNano(), filepath.Base(path))
	if err := os.WriteFile(filepath.Join(backupDir, name), current, 0o600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	pruneBackups(backupDir, filepath.Base(path))
	return nil
}

// pruneBackups removes the oldest backups of one base name beyond the newest
// backupKeep. Errors are ignored: pruning must never fail a save. The first
// 19 characters of a backup name are the zero-padded UnixNano timestamp, so
// lexicographic order equals chronological order.
func pruneBackups(backupDir, baseName string) {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return
	}
	var ours []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || len(n) < 21 || n[19] != '-' || n[20:] != baseName {
			continue
		}
		ours = append(ours, n)
	}
	if len(ours) <= backupKeep {
		return
	}
	excess := len(ours) - backupKeep
	for i := 0; i < excess; i++ {
		_ = os.Remove(filepath.Join(backupDir, ours[i]))
	}
}

// syncDir best-effort fsyncs the directory so renames are durable.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// DefaultComposeContent is offered by the editor when the stack has no main
// compose file yet: a minimal, valid model.
const DefaultComposeContent = `services:
  app:
    image: example/app:latest
    # container_name:
    # ports:
    # volumes:
    # environment:
`

// DefaultEnvContent is offered when .env does not exist yet.
const DefaultEnvContent = "# KEY=value pairs for substitution in docker-compose.yml\n"
