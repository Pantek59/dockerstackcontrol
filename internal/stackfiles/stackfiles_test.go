package stackfiles

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile creates a regular file with the given content and returns the
// directory it was written to (also handy for building a stack directory).
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestJoinPath(t *testing.T) {
	for _, wantOK := range []struct {
		dir, name string
		ok        bool
	}{
		{"/stacks/media", "docker-compose.yml", true},
		{"/stacks/media", ".env", true},
		{"/stacks/media", "compose.yaml", true},
		{"stacks/media", "compose.yaml", false}, // relative
		{"/stacks/../stacks/media", "x.yml", false},
		{"/stacks/./media/", "x.yml", false},
		{"/stacks/media", "", false},
		{"/stacks/media", "../escape.yml", false},
		{"/stacks/media", "/abs.yml", false}, // not a plain name
		{"/stacks/media", "a b.yml", false},
		{"/stacks/media", "..hidden", false}, // dot file other than .env
		{"/stacks/media", ".", false},
		{"/stacks/media", "..", false},
		{"", "x.yml", false},
	} {
		_, err := joinPath(wantOK.dir, wantOK.name)
		if wantOK.ok != (err == nil) {
			t.Errorf("joinPath(%q, %q) error = %v, want ok=%v", wantOK.dir, wantOK.name, err, wantOK.ok)
		}
	}
}

func TestResolveFileDetectionOrder(t *testing.T) {
	dir := t.TempDir()

	// Nothing exists yet: compose resolves to the conventional name.
	f, ok, err := ResolveFile(dir, "", KindCompose)
	if err != nil || !ok {
		t.Fatalf("ResolveFile() = %v, %v, %v", f, ok, err)
	}
	if f.Name != MainComposeFile || f.Exists {
		t.Errorf("file = %+v, want absent %s", f, MainComposeFile)
	}
	if f.Path != filepath.Join(dir, MainComposeFile) {
		t.Errorf("path = %q", f.Path)
	}

	// The .env file has a fixed name.
	f, _, err = ResolveFile(dir, "", KindEnv)
	if err != nil || f.Name != EnvFileName || f.Exists {
		t.Errorf("env file = %+v, err %v", f, err)
	}
	if f.Path != filepath.Join(dir, EnvFileName) {
		t.Errorf("env path = %q", f.Path)
	}

	// Existing regular files are resolved and described.
	writeFile(t, filepath.Join(dir, "compose.yaml"), "services: {}\n")
	f, ok, err = ResolveFile(dir, "", KindCompose)
	if err != nil || !ok || !f.Exists || f.Name != "compose.yaml" || f.Size == 0 {
		t.Errorf("after create, file = %+v, err %v", f, err)
	}

	// An explicit override wins over detection.
	writeFile(t, filepath.Join(dir, "custom.yml"), "services: {}\n")
	f, _, err = ResolveFile(dir, "custom.yml", KindCompose)
	if err != nil || f.Name != "custom.yml" || !f.Exists {
		t.Errorf("override ignored: %+v, err %v", f, err)
	}

	// No directory configured: ok=false, no error.
	if _, ok, err := ResolveFile("", "", KindCompose); err != nil || ok {
		t.Errorf("ResolveFile(\"\") = ok %v, err %v, want ok=false", ok, err)
	}
	if _, ok, err := ResolveFile("", "", "bogus"); err == nil || ok {
		t.Error("unknown kind accepted")
	}
}

func TestResolveFileIrregularRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), filepath.Join(dir, MainComposeFile)); err != nil {
		t.Skip("symlink not supported:", err)
	}
	f, ok, err := ResolveFile(dir, "", KindCompose)
	if err != nil || !ok {
		t.Fatalf("ResolveFile error = %v", err)
	}
	if f.Exists || !f.Irregular {
		t.Errorf("file = %+v, want Exists=false Irregular=true", f)
	}
	// And reads refuse it, too.
	if _, err := Read(filepath.Join(dir, MainComposeFile)); !errors.Is(err, ErrNotRegular) {
		t.Errorf("Read(symlink) = %v, want ErrNotRegular", err)
	}
}

func TestReadAndSaveRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, MainComposeFile)
	writeFile(t, path, "services:\n  app:\n    image: nginx\n")

	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got.Text != "services:\n  app:\n    image: nginx\n" {
		t.Errorf("Text = %q", got.Text)
	}
	if got.Hash == "" || got.Hash != hashOf(got.Text) {
		t.Errorf("Hash mismatch")
	}
	if got.Modified.IsZero() {
		t.Error("Modified not set")
	}

	newer := got.Text + "    ports:\n"
	if err := Save(dir, path, newer, got.Hash); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != newer {
		t.Fatalf("after save, file = %q, err %v", raw, err)
	}

	// Re-read yields the new hash (the editor attests it for the next save).
	after, err := Read(path)
	if err != nil || after.Text != newer {
		t.Fatalf("Read after save = %+v, err %v", after, err)
	}
}

func TestSaveDetectsConflicts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, MainComposeFile)
	writeFile(t, path, "a: 1\n")

	// Wrong hash.
	if err := Save(dir, path, "a: 2\n", strings.Repeat("0", 64)); !errors.Is(err, ErrConflict) {
		t.Errorf("stale hash: %v, want ErrConflict", err)
	}
	// Empty base hash on an existing file.
	if err := Save(dir, path, "a: 2\n", ""); !errors.Is(err, ErrConflict) {
		t.Errorf("empty hash on existing file: %v, want ErrConflict", err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != "a: 1\n" {
		t.Errorf("conflicting saves must not change the file, have %q", raw)
	}

	// Correct hash works, and an empty hash then conflicts again.
	if err := Save(dir, path, "a: 2\n", hashOf("a: 1\n")); err != nil {
		t.Errorf("correct hash: %v", err)
	}
	if err := Save(dir, path, "a: 3\n", hashOf("a: 1\n")); !errors.Is(err, ErrConflict) {
		t.Errorf("old hash after write: %v, want ErrConflict", err)
	}
}

func TestSaveCreateNewAndRace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, EnvFileName)

	// Creating an absent file is allowed with an empty base hash.
	if err := Save(dir, path, "KEY=1\n", ""); err != nil {
		t.Fatalf("Save(create) = %v", err)
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "KEY=1\n" {
		t.Errorf("saved %q", raw)
	}

	// But the attestation of absence becomes a conflict once the file
	// exists: a concurrent creation is never silently overwritten.
	if err := Save(dir, path, "KEY=2\n", ""); !errors.Is(err, ErrConflict) {
		t.Errorf("Save(race) = %v, want ErrConflict", err)
	}

	// And vice versa: attesting a version for a file that has disappeared.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, path, "KEY=3\n", hashOf("KEY=1\n")); !errors.Is(err, ErrConflict) {
		t.Errorf("Save(deleted) = %v, want ErrConflict", err)
	}
}

func TestSaveContentGuards(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, MainComposeFile)

	tooBig := strings.Repeat("a", MaxFileSize+1)
	if err := Save(dir, path, tooBig, ""); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Save(too large) = %v, want ErrTooLarge", err)
	}
	if err := Save(dir, path, "has\x00nul", ""); !errors.Is(err, ErrBadContent) {
		t.Errorf("Save(NUL) = %v, want ErrBadContent", err)
	}
	if err := Save(dir, path, string([]byte{0xff, 0xfe}), ""); !errors.Is(err, ErrBadContent) {
		t.Errorf("Save(invalid utf8) = %v, want ErrBadContent", err)
	}
	// Missing stack directory.
	if err := Save(filepath.Join(dir, "missing"), filepath.Join(dir, "missing", "x.yml"), "x", ""); err == nil {
		t.Error("Save(missing dir) succeeded")
	}
}

func TestReadGuards(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.yml")
	writeFile(t, path, strings.Repeat("a", MaxFileSize+1))
	if _, err := Read(path); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Read(too large) = %v, want ErrTooLarge", err)
	}

	writeFile(t, path, "text\x00with nul")
	if _, err := Read(path); !errors.Is(err, ErrBadContent) {
		t.Errorf("Read(NUL) = %v, want ErrBadContent", err)
	}

	writeFile(t, path, string([]byte{0xff, 0xfe, 0xfd}))
	if _, err := Read(path); !errors.Is(err, ErrBadContent) {
		t.Errorf("Read(invalid utf8) = %v, want ErrBadContent", err)
	}

	if _, err := Read(filepath.Join(dir, "absent.yml")); !errors.Is(err, ErrNotFound) {
		t.Errorf("Read(absent) = %v, want ErrNotFound", err)
	}
	if _, err := Read(dir); !errors.Is(err, ErrNotRegular) {
		t.Errorf("Read(directory) = %v, want ErrNotRegular", err)
	}
}

func TestReadFollowsNothingSymlink(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.txt")
	writeFile(t, secret, "host secrets")
	if err := os.Symlink(secret, filepath.Join(dir, "link.yml")); err != nil {
		t.Skip("symlink not supported:", err)
	}
	if _, err := Read(filepath.Join(dir, "link.yml")); !errors.Is(err, ErrNotRegular) {
		t.Errorf("Read(symlink) = %v, want ErrNotRegular", err)
	}
}

func TestSaveNeverFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside.txt")
	writeFile(t, target, "do not touch")
	link := filepath.Join(dir, "docker-compose.yml")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink not supported:", err)
	}

	if err := Save(dir, link, "evil content", ""); !errors.Is(err, ErrNotRegular) {
		t.Errorf("Save(symlink) = %v, want ErrNotRegular", err)
	}
	if raw, _ := os.ReadFile(target); string(raw) != "do not touch" {
		t.Errorf("symlink was followed: target now %q", raw)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("symlink itself removed: %v", err)
	}
}

func TestSaveKeepsModeAndCreatesConventionalModes(t *testing.T) {
	dir := t.TempDir()

	// New .env gets 0600.
	env := filepath.Join(dir, EnvFileName)
	if err := Save(dir, env, "KEY=x\n", ""); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(env); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf(".env mode = %v, want 0600", info.Mode().Perm())
	}

	// New compose file gets 0644.
	compose := filepath.Join(dir, MainComposeFile)
	if err := Save(dir, compose, "services: {}\n", ""); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(compose); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("compose mode = %v, want 0644", info.Mode().Perm())
	}

	// An existing unreadable mode is preserved only when owner-writable;
	// otherwise the conventional default applies (the new file must stay
	// writable by stackctl itself).
	if err := os.Chmod(compose, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, compose, "services: {x: null}\n", hashOf("services: {}\n")); err != nil {
		t.Fatalf("Save(readonly current) = %v", err)
	}
	if info, err := os.Lstat(compose); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("compose mode after save = %v, want 0644", info.Mode().Perm())
	}
	if err := os.Chmod(compose, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, compose, "services:\n  a: null\n", hashOf("services: {x: null}\n")); err != nil {
		t.Fatalf("Save(0640 current) = %v", err)
	}
	if info, err := os.Lstat(compose); err != nil || info.Mode().Perm() != 0o640 {
		t.Errorf("compose mode preserved = %v, want 0640", info.Mode().Perm())
	}
}

func TestBackupsRotate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, MainComposeFile)

	if err := Save(dir, path, "v0\n", ""); err != nil {
		t.Fatal(err) // create
	}
	previous := "v0\n"
	for i := 1; i <= backupKeep+3; i++ {
		current := hashOf(previous)
		next := strings.Repeat("v", 1) + strings.Repeat("0"+string(rune('0'+i)), i) + "\n"
		if err := Save(dir, path, next, current); err != nil {
			t.Fatalf("Save(v%d) = %v", i, err)
		}
		previous = next
	}

	entries, err := os.ReadDir(BackupDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	ours := 0
	for _, e := range entries {
		if e.IsDir() || len(e.Name()) < 21 || e.Name()[19] != '-' || e.Name()[20:] != MainComposeFile {
			continue
		}
		ours++
	}
	if ours != backupKeep {
		t.Errorf("backups kept = %d, want %d", ours, backupKeep)
	}
	if info, err := os.Stat(BackupDir(dir)); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("backup dir mode = %v, want 0700", info.Mode().Perm())
	}

	// The oldest backup must hold v0 — the newest must hold the final value.
	raw, _ := os.ReadFile(path)
	if string(raw) != previous {
		t.Errorf("current file = %q, want %q", raw, previous)
	}
}

func TestListStackFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, MainComposeFile), "services: {}\n")

	files, ok, err := ListStackFiles(dir, "")
	if err != nil || !ok {
		t.Fatalf("ListStackFiles() = %v, %v, %v", files, ok, err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %d, want 2", len(files))
	}
	if files[0].Kind != KindCompose || files[0].Name != MainComposeFile {
		t.Errorf("files[0] = %+v", files[0])
	}
	if files[1].Kind != KindEnv || files[1].Exists {
		t.Errorf("files[1] = %+v, want absent .env", files[1])
	}

	if _, ok, _ := ListStackFiles("", ""); ok {
		t.Error("ListStackFiles(\"\") must report ok=false")
	}
}

func TestResolveCompose(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, MainComposeFile), "services: {}\n")

	path, ok, err := ResolveCompose(dir, "")
	if err != nil || !ok || path != filepath.Join(dir, MainComposeFile) {
		t.Fatalf("ResolveCompose = %q, %v, %v", path, ok, err)
	}

	// Missing model (e.g. dir not mounted): clear error, and NOT ok=false
	// (ok=false is reserved for "no dir configured").
	if _, ok, err := ResolveCompose(filepath.Join(dir, "nope"), ""); !ok || !errors.Is(err, ErrNotFound) {
		t.Errorf("ResolveCompose(missing dir) = ok %v, err %v, want ErrNotFound with ok=true", ok, err)
	}

	// A non-regular detected file is not a model.
	if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "override.yml")); err != nil {
		t.Skip("symlink not supported:", err)
	}
	if _, _, err := ResolveCompose(dir, "override.yml"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ResolveCompose(symlink override) err = %v, want ErrNotFound", err)
	}

	// No dir configured.
	if _, ok, _ := ResolveCompose("", ""); ok {
		t.Error("ResolveCompose(\"\") must report ok=false")
	}
}

func TestDefaultContentsValidate(t *testing.T) {
	// The scaffolds the editor offers must be plain, useful text.
	if !strings.Contains(DefaultComposeContent, "services:") {
		t.Errorf("compose scaffold = %q, want a services skeleton", DefaultComposeContent)
	}
	if !strings.Contains(DefaultEnvContent, "=") || strings.HasPrefix(DefaultEnvContent, "#;") {
		t.Errorf("env scaffold = %q", DefaultEnvContent)
	}
}
