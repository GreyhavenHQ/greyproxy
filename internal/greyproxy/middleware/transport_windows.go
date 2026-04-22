//go:build windows

package middleware

import (
	"os"
	"os/exec"
	"syscall"
)

// configureProcessGroup is a no-op on Windows. Process groups work
// differently (job objects); a future Windows-targeted release can add
// CREATE_NEW_PROCESS_GROUP here, but greyproxy is primarily unix today.
func configureProcessGroup(cmd *exec.Cmd) {}

// killProcessGroup falls back to killing just the top-level process.
func killProcessGroup(p *os.Process) {
	if p == nil {
		return
	}
	_ = p.Signal(syscall.SIGKILL)
}
