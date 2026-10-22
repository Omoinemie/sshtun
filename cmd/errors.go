package cmd

import (
	"errors"
	"fmt"

	"github.com/Omoinemie/sshtun/internal/daemon"
)

var (
	errNoTunnels         = errors.New("no enabled tunnel in the database; add one with `sshtun db tunnel add` first")
	errNoSelectedTunnels = errors.New("none of the given tunnels exists or is enabled, there is nothing to start")
	errNeedPrivilege     = errors.New("TUN mode needs privileges: run as root on Linux, as an administrator on Windows")
)

func errRunning(s *daemon.State) error {
	return fmt.Errorf("an instance is already running (pid=%d, mode=%s), run `sshtun stop` first", s.Pid, s.Mode)
}
