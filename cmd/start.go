package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/daemon"
	"github.com/Omoinemie/sshtun/internal/sshclient"
	"github.com/Omoinemie/sshtun/internal/store"
)

const daemonEnv = "SSHSTUN_INTERNAL_DAEMON"

var startDaemon bool

var startCmd = &cobra.Command{
	Use:   "start [tunnel|all]",
	Short: "Start tunnels (all enabled ones by default; names may be given, separated by commas)",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		names := parseTunnelArgs(args)
		cfg, err := configLoad()
		if err != nil {
			return err
		}
		// 已有实例在运行时：全部 → 报错；指定名称 → 仅新增这些隧道。
		if s, _ := daemon.ActiveState(); s != nil {
			if isAllNames(names) {
				return errRunning(s)
			}
			return sendControl(opStart, names)
		}
		return startInstance(cfg, names, startDaemon)
	},
}

// startInstance 启动一个新实例。background 为真时后台化运行。
func startInstance(cfg *config.Config, names []string, background bool) error {
	// 后台守护模式（父进程负责前台自检与后台化，子进程直接运行）。
	if background && os.Getenv(daemonEnv) != "1" {
		if s, _ := daemon.ActiveState(); s != nil {
			return errRunning(s)
		}
		// 后台化之前先对每条隧道做一次真实登录自检：密码不被接受时可在（仍连着
		// 终端的）前台重新输入并加密回写数据库，未受信任的主机也在此确认并写入
		// 信任存储。子进程随后只复用已保存的密文，不再交互。
		if err := precheckTunnels(cfg, names); err != nil {
			return fmt.Errorf("pre-start login check failed: %w", err)
		}
		pid, err := daemon.Daemonize(os.Args[1:], map[string]string{daemonEnv: "1"})
		if err != nil {
			return err
		}
		fmt.Printf("Background process started pid=%d\n", pid)
		// 等待 state.json 就绪
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if !daemon.IsAlive(pid) {
				return errors.New("the background process exited early, run `sshtun start` in the foreground to diagnose")
			}
			if s, _ := daemon.ActiveState(); s != nil && s.Pid == pid {
				fmt.Println("Started successfully (see the log in the [log] dir of the config file, or run in the foreground to watch it)")
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
		return errors.New("timed out waiting for the background process to become ready")
	}

	if s, _ := daemon.ActiveState(); s != nil {
		return errRunning(s)
	}
	return runSession(cfg, ModeTun, names)
}

// parseTunnelArgs 把位置参数解析为隧道名列表：多个名称可用逗号或空格分隔。
// 返回空切片表示「全部启用隧道」。
func parseTunnelArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	var out []string
	for _, p := range strings.Split(strings.Join(args, ","), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// precheckTunnels 在后台化前逐条登录选中的隧道，以便前台交互式地解析/回写凭据。
// 任一条失败即中止（避免后台子进程无法交互而空转）。
func precheckTunnels(base *config.Config, names []string) error {
	st, err := store.Open(base.App.DB)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	tunnels, err := resolveTunnels(st, names)
	if err != nil {
		return err
	}
	if len(tunnels) == 0 {
		return errNoTunnels
	}
	for _, t := range tunnels {
		rt := t.RuntimeConfig(base)
		cli := sshclient.New(rt)
		if isInteractive() {
			cli.PromptHostKey = interactiveHostKey()
		}
		err := connectWithPassword(rt, cli, dbSaver{st: st, name: t.Name})
		_ = cli.Close()
		if err != nil {
			return fmt.Errorf("tunnel %s: %w", t.Name, err)
		}
	}
	return nil
}

func init() {
	startCmd.Flags().BoolVarP(&startDaemon, "daemon", "d", false, "run in the background")
}
