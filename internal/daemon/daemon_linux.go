//go:build linux

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Daemonize 以自身重新执行的方式启动后台守护进程（setsid 脱离终端）。
// args 是子进程的命令行参数（不含程序名）；additionalEnv 追加到子进程的环境变量。
// 返回后当前进程应直接退出（成功时）。
func Daemonize(args []string, additionalEnv map[string]string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	cmd := exec.Command(exe, args...)
	for k, v := range additionalEnv {
		cmd.Env = append(os.Environ(), k+"="+v)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start the background process: %w", err)
	}
	pid := cmd.Process.Pid
	// 回收子进程：父进程长期存活时（如 Web 界面派生守护实例），若不 wait，
	// 子进程结束后会残留为僵尸，而 kill(pid, 0) 对僵尸仍然成功，
	// 会使 IsAlive 误判为存活，隧道锁因而无法释放。
	go func() { _ = cmd.Wait() }()
	return pid, nil
}

// IsAlive 探测进程是否存活。
func IsAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// KillPid 先发 SIGTERM，宽限 5 秒后强制 SIGKILL。
func KillPid(pid int) error {
	if !IsAlive(pid) {
		return nil
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !IsAlive(pid) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	return nil
}
