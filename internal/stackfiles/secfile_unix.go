//go:build !windows

package stackfiles

import (
	"errors"
	"os"
	"syscall"
)

// openGuarded opens path with the given flags and mode plus the O_NOFOLLOW
// guard: a trailing symlink is refused instead of followed. On Windows the
// sibling file provides the portable variant (see secfile_windows.go).
func openGuarded(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag|syscall.O_NOFOLLOW, perm)
}

// mapGuardedErr translates guard-specific open errors (ELOOP from O_NOFOLLOW)
// to the sentinel errors. On Windows the sibling file provides the portable
// variant.
func mapGuardedErr(err error) error {
	if errors.Is(err, syscall.ELOOP) {
		return ErrNotRegular
	}
	return err
}
