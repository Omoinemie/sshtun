//go:build !windows && !linux

package tun2socks

import "os/exec"

// prepareChild 其它平台暂无内核级的父子进程联动，保持无操作。
func prepareChild(cmd *exec.Cmd) {}

// guardChild 其它平台暂无可用的兜底清理，保持无操作。
func guardChild(cmd *exec.Cmd) {}
