//go:build windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// Daemonize 以自身重新执行的方式启动后台守护进程（DETACHED_PROCESS）。
//
// args 是子进程的命令行参数（不含程序名）；additionalEnv 追加到子进程的环境变量。
//
// Windows 下 DETACHED_PROCESS 的子进程继承父进程访问令牌，
// 因此管理员权限会自动延续，无需二次 UAC 授权。
func Daemonize(args []string, additionalEnv map[string]string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	cmd := exec.Command(exe, args...)
	for k, v := range additionalEnv {
		cmd.Env = append(os.Environ(), k+"="+v)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start the background process: %w", err)
	}
	pid := cmd.Process.Pid
	// 回收子进程：父进程长期存活时（如 Web 界面派生守护实例），若不回收，
	// 已结束的子进程会因句柄仍被持有而残留为「僵尸」，使 IsAlive 误判为存活，
	// 隧道锁因而无法释放。子进程结束后本协程随即返回，句柄随之关闭。
	go func() { _ = cmd.Wait() }()
	return pid, nil
}

// stillActive 是 Windows 的 STILL_ACTIVE(259)：进程仍在运行时
// GetExitCodeProcess 返回该值；已结束时返回其退出码。
const stillActive = 259

// IsAlive 探测进程是否存活。
//
// 仅凭 OpenProcess 成功不足以判断存活：进程被强杀后，只要仍有句柄打开
// （例如派生它的父进程尚未回收它），进程对象依然存在，OpenProcess 仍会成功。
// 因此还要读退出码——已结束的进程返回退出码，只有仍在运行才是 STILL_ACTIVE。
func IsAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}

// KillPid Windows 上使用 taskkill 强制结束（无 Unix 信号语义）。
func KillPid(pid int) error {
	if !IsAlive(pid) {
		return nil
	}
	cmd := exec.Command("taskkill", "/PID", fmt.Sprint(pid), "/T", "/F")
	// 后台模式下守护进程没有控制台，taskkill 若新建控制台会闪现黑色小窗。
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd.Run()
}
