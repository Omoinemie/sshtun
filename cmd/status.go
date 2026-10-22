package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/Omoinemie/sshtun/internal/daemon"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the running state",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := daemon.LoadState()
		if err != nil {
			return err
		}
		if s == nil || !daemon.IsAlive(s.Pid) {
			fmt.Println("sshtun is not running")
			return nil
		}
		fmt.Println("sshtun is running")
		fmt.Printf("  Main PID:  pid=%d, started %s (up %s)\n",
			s.Pid, s.StartedAt.Format("2006-01-02 15:04:05"), time.Since(s.StartedAt).Round(time.Second))
		fmt.Printf("  Mode:      %s\n", s.Mode)
		fmt.Printf("  Config:    %s\n", s.ConfigPath)
		if s.DBPath != "" {
			fmt.Printf("  Database:  %s\n", s.DBPath)
		}
		if len(s.Tunnels) == 0 {
			fmt.Println("  (no tunnel state recorded)")
			return nil
		}
		for _, t := range s.Tunnels {
			fmt.Printf("  Tunnel %s:\n", t.Name)
			fmt.Printf("    SOCKS5:   %s\n", t.Listen)
			if t.Tun2socksPid > 0 {
				state := "running"
				if !daemon.IsAlive(t.Tun2socksPid) {
					state = "exited"
				}
				fmt.Printf("    tun2socks: pid=%d (%s)\n", t.Tun2socksPid, state)
				fmt.Printf("    TUN if:   %s\n", t.Iface)
			}
			// 流量统计为应用层计数：TUN 经 SOCKS5、端口转发经各自管道（见 stats.go）。
			fmt.Printf("    Traffic:  up %s (%s)  down %s (%s)\n",
				fmtBytes(t.Up), fmtRate(t.UpSpeed),
				fmtBytes(t.Down), fmtRate(t.DownSpeed))
			if len(t.Routes) > 0 {
				fmt.Println("    Active routes:")
				for _, r := range t.Routes {
					fmt.Printf("      %-16s %s -> %s\n", r.CIDR, r.Kind, r.Gateway)
				}
			}
		}
		return nil
	},
}
