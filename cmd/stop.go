package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Omoinemie/sshtun/internal/daemon"
	"github.com/Omoinemie/sshtun/internal/routing"
)

var stopCmd = &cobra.Command{
	Use:   "stop [tunnel|all]",
	Short: "Stop running tunnels (all by default; names may be given, separated by commas)",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		names := parseTunnelArgs(args)
		s, err := daemon.LoadState()
		if err != nil {
			return err
		}
		if s == nil {
			fmt.Println("No running state found (state.json does not exist), nothing to stop")
			return nil
		}
		if !daemon.IsAlive(s.Pid) {
			if err := cleanupState(s); err != nil {
				return err
			}
			fmt.Println("sshtun is not running (stale state cleaned up)")
			return nil
		}

		if isAllNames(names) {
			return stopAll(s)
		}
		matched := matchRunning(s, names)
		if len(matched) == 0 {
			fmt.Println("None of the given tunnels is running")
			return nil
		}
		if len(matched) == len(s.Tunnels) {
			return stopAll(s)
		}
		return sendControl(opStop, matched)
	},
}

// stopAll 停止整个实例：结束主进程并清理全部隧道的资源与状态。
func stopAll(s *daemon.State) error {
	// 1. 停止主进程（其信号处理器会做优雅清理；Windows 为强制结束）
	if s.Pid > 0 && daemon.IsAlive(s.Pid) {
		fmt.Printf("Stopping main process pid=%d ...\n", s.Pid)
		if err := daemon.KillPid(s.Pid); err != nil {
			fmt.Printf("Failed to stop the main process (continuing cleanup): %v\n", err)
		}
	}
	if err := cleanupState(s); err != nil {
		return err
	}
	fmt.Println("sshtun has stopped")
	return nil
}

// cleanupState 清理状态记录中的隧道资源并删除 state.json（幂等）。
func cleanupState(s *daemon.State) error {
	// 确保各隧道的 tun2socks 子进程已退出（父进程被强杀时可能遗留）
	for _, t := range s.Tunnels {
		if t.Tun2socksPid > 0 && daemon.IsAlive(t.Tun2socksPid) {
			fmt.Printf("Stopping tun2socks pid=%d of tunnel %s ...\n", t.Tun2socksPid, t.Name)
			if err := daemon.KillPid(t.Tun2socksPid); err != nil {
				fmt.Printf("Failed to stop tun2socks (tunnel %s): %v\n", t.Name, err)
			}
		}
	}
	// 释放隧道占用锁：主进程被强杀时来不及释放，锁文件会残留。
	for _, t := range s.Tunnels {
		daemon.ReleaseTunnelLock(t.Name)
	}
	// 逐隧道清理路由（幂等）
	for _, t := range s.Tunnels {
		if len(t.Routes) > 0 {
			fmt.Printf("Cleaning up %d route(s) of tunnel %s ...\n", len(t.Routes), t.Name)
			routing.Teardown(t.Routes, t.Iface)
		}
	}
	cleanControlFiles()
	return daemon.ClearState()
}

// matchRunning 从运行状态中筛选出仍在运行的目标隧道名，并告警未运行的名字。
func matchRunning(s *daemon.State, names []string) []string {
	running := map[string]bool{}
	for _, t := range s.Tunnels {
		running[t.Name] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		if !running[n] {
			fmt.Printf("Warning: tunnel %q is not running, skipping\n", n)
			continue
		}
		out = append(out, n)
	}
	return out
}
