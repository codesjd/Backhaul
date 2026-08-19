//go:build windows

package cmd

// raiseFileLimit is a no-op on Windows, which has no RLIMIT_NOFILE. It is only
// ever called inside a runtime GOOS=="linux" guard, so it never runs here; this
// stub exists solely so the package compiles on Windows (a dev-only target).
func raiseFileLimit() {}
