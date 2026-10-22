package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Omoinemie/sshtun/internal/daemon"
	"github.com/Omoinemie/sshtun/internal/store"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tunnels with their state, route and forward counts",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := configLoad()
		if err != nil {
			return err
		}
		st, err := store.Open(cfg.App.DB)
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()

		tunnels, err := st.ListTunnels()
		if err != nil {
			return err
		}
		if len(tunnels) == 0 {
			fmt.Println("(no tunnels in the database; add one with `sshtun db tunnel add`)")
			return nil
		}

		running := map[string]bool{}
		trafficByName := map[string]daemon.TunnelState{}
		if s, _ := daemon.ActiveState(); s != nil {
			for _, t := range s.Tunnels {
				running[t.Name] = true
				trafficByName[t.Name] = t
			}
		}

		fmt.Printf("%-20s %-8s %-6s %-26s %-22s %-6s %-4s %s\n",
			"NAME", "ENABLED", "RUNNING", "SSH", "TUN", "ROUTES", "FWD", "TRAFFIC(up/down)")
		for _, t := range tunnels {
			enabled := "no"
			if t.Enabled {
				enabled = "yes"
			}
			run := "no"
			if running[t.Name] {
				run = "yes"
			}
			ssh := fmt.Sprintf("%s@%s:%d", t.SSHUser, t.SSHHost, t.SSHPort)
			tun := fmt.Sprintf("%s (%s)", t.TunName, t.TunAddress)
			// 流量仅运行中的隧道有值（应用层计数，含端口转发；见 stats.go）。
			traffic := "-"
			if st, ok := trafficByName[t.Name]; ok && run == "yes" {
				traffic = fmt.Sprintf("↑%s ↓%s", fmtBytes(st.Up), fmtBytes(st.Down))
			}
			fmt.Printf("%-20s %-8s %-6s %-26s %-22s %-6d %-4d %s\n",
				t.Name, enabled, run, ssh, tun, len(t.Routes), len(t.Forwards), traffic)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
