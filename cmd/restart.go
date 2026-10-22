package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Omoinemie/sshtun/internal/daemon"
)

var restartDaemon bool

var restartCmd = &cobra.Command{
	Use:   "restart [tunnel|all]",
	Short: "Restart tunnels (all by default; names may be given, separated by commas)",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		names := parseTunnelArgs(args)
		cfg, err := configLoad()
		if err != nil {
			return err
		}
		s, _ := daemon.ActiveState()
		if s == nil {
			fmt.Println("No running instance detected, starting one")
			return startInstance(cfg, names, restartDaemon)
		}
		// 全部重启：整体停止后重新启动。
		if isAllNames(names) {
			if err := stopAll(s); err != nil {
				return err
			}
			return startInstance(cfg, nil, restartDaemon)
		}
		// 指定子集：由主进程在原实例内原地重启，其余隧道不受影响。
		return sendControl(opRestart, names)
	},
}

func init() {
	restartCmd.Flags().BoolVarP(&restartDaemon, "daemon", "d", false, "run in the background (only when no running instance is detected)")
}
