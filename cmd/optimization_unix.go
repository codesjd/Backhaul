//go:build !windows

package cmd

import "syscall"

// raiseFileLimit bumps the process open-file limit (RLIMIT_NOFILE) to 1048576 so
// a large tunnel pool doesn't exhaust descriptors. Unix-only: Windows has no
// rlimit, so the build there uses the no-op in optimization_windows.go.
func raiseFileLimit() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		logger.Errorf("Error getting Rlimit: %v", err)
		return
	}
	logger.Debugf("Current file descriptor limit: %d", rLimit.Cur)
	rLimit.Max = 1048576
	rLimit.Cur = 1048576
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		logger.Errorf("Error setting Rlimit: %v", err)
		return
	}
	logger.Debugf("Successfully set file descriptor limit to: %d", rLimit.Cur)
}
