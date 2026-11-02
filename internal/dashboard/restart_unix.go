//go:build unix

package dashboard

import (
	"os"
	"syscall"
)

func signalStop() {
	p, err := os.FindProcess(os.Getpid())
	if err == nil {
		_ = p.Signal(syscall.SIGTERM)
	}
}
