//go:build unix

package middleware

import (
	"os"
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the child in its own process group. Without
// this, `cmd.Process.Signal(SIGKILL)` only kills the immediate child, so
// a command like `uv run mw.py` leaves the actual Python interpreter
// alive and reparented to init — keeping whatever ports or files it had
// open. With Setpgid=true we can signal -pgid and reap the whole group.
func configureProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcessGroup SIGKILLs every process in p's group. Falls back to
// signalling only p if the group lookup fails (child already exited,
// or platform quirk).
func killProcessGroup(p *os.Process) {
	if p == nil {
		return
	}
	pgid, err := syscall.Getpgid(p.Pid)
	if err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	}
	_ = p.Signal(syscall.SIGKILL)
}
