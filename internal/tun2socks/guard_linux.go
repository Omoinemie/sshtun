//go:build linux

package tun2socks

import (
	"os/exec"
	"syscall"
)

// prepareChild 让内核在 sshtun 退出（含被强杀）时向 tun2socks 发送 SIGKILL。
// PR_SET_PDEATHSIG 在 fork 时随子进程一并设置，是 Linux 上唯一的内核级兜底，
// 无需额外清理代码。
func prepareChild(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}

// guardChild Linux 已由 Pdeathsig 兜底，无需启动后处理。
func guardChild(cmd *exec.Cmd) {}
