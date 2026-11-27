//go:build windows

package stackfiles

import "os"

// openGuarded is the Windows variant of the guarded open: the O_NOFOLLOW
// flag does not exist on Windows, so the open itself follows a trailing
// symlink (a documented best-effort limitation; callers already verify the
// path is a regular file, and the editor API only ever targets paths the
// administrator configured).
func openGuarded(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm)
}

// mapGuardedErr is the Windows variant of the guarded open error mapping: no
// O_NOFOLLOW guard exists, so there is no ELOOP to translate.
func mapGuardedErr(err error) error {
	return err
}
