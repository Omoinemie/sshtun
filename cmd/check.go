package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/secret"
	"github.com/Omoinemie/sshtun/internal/socks5"
	"github.com/Omoinemie/sshtun/internal/sshclient"
	"github.com/Omoinemie/sshtun/internal/store"
	"github.com/Omoinemie/sshtun/internal/tun2socks"
)

var checkConnect bool

// probeForwardTarget 是探测对端转发能力时使用的目标：取对端本机一个几乎不会有
// 监听的端口。通道被允许但目标不可达时对端返回 "connect failed"（说明转发可用），
// 被策略拒绝时返回 "administratively prohibited"（说明转发被禁）。
const probeForwardTarget = "127.0.0.1:1"

var checkCmd = &cobra.Command{
	Use:   "check [tunnel|all]",
	Short: "Validate the basic config and the tunnels in the database, and self-test the runtime environment (names may be given, all by default)",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		names := parseTunnelArgs(args)
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		pass := func(msg string) { fmt.Printf("[OK]   %s\n", msg) }
		warn := func(msg string) { fmt.Printf("[WARN] %s\n", msg) }
		fail := func(msg string) { fmt.Printf("[FAIL] %s\n", msg) }

		fmt.Printf("sshtun check - config file: %s\n", cfgFile)
		pass("basic config parsed successfully")
		fmt.Printf("Database: %s\n", cfg.App.DB)
		pass(fmt.Sprintf("SOCKS5 listener: %s (one per tunnel, the port is picked by the system)", socks5.ListenAddr))

		st, err := store.Open(cfg.App.DB)
		if err != nil {
			fail("failed to open the database: " + err.Error())
			return err
		}
		defer func() { _ = st.Close() }()
		pass("database is readable")

		tunnels, err := st.ListTunnels()
		if err != nil {
			fail("failed to read the tunnels: " + err.Error())
			return err
		}
		tunnels = filterTunnelsByName(tunnels, names)
		if len(tunnels) == 0 {
			warn("no matching tunnel; add one with `sshtun db tunnel add`, and routes/forwards with `sshtun db route/forward add`")
			return nil
		}

		// 启用隧道的唯一性校验（TUN 名/地址不可冲突）。
		var enabled []*store.Tunnel
		for _, t := range tunnels {
			if t.Enabled {
				enabled = append(enabled, t)
			}
		}
		if err := validateUniqueTunnels(enabled); err != nil {
			fail("the uniqueness/integrity check of the enabled tunnels failed:\n" + indent(err.Error()))
		} else {
			pass(fmt.Sprintf("TUN name/address uniqueness check passed (%d enabled tunnel(s))", len(enabled)))
		}

		var connectErrs []error
		for _, t := range tunnels {
			rt := t.RuntimeConfig(cfg)
			state := "disabled"
			if t.Enabled {
				state = "enabled"
			}
			fmt.Printf("\n[tunnel] %s (%s)\n", t.Name, state)

			if err := rt.ValidateTunnel(); err != nil {
				fail("invalid tunnel parameters: " + err.Error())
				continue
			}
			pass(fmt.Sprintf("SSH parameters are valid (%s@%s:%d, auth=%s)", rt.SSH.User, rt.SSH.Host, rt.SSH.Port, rt.SSH.Auth))

			if rt.HostKeyStrict() {
				pass(fmt.Sprintf("host key verification: enabled (known_hosts=%s)", rt.SSH.HostKey))
			} else {
				warn("host key verification: disabled (host_key=none, the peer identity is not checked)")
			}

			if rt.SSH.Auth == "password" {
				switch {
				case secret.IsEncrypted(rt.SSH.Password):
					if _, derr := secret.Decrypt(rt.SSH.Password); derr != nil {
						warn("login password: the ciphertext cannot be decrypted (it is bound to this machine's machine code, so it breaks on another machine or after a hostname change); it will be re-entered at connect time")
					} else {
						pass("login password: stored encrypted")
					}
				default:
					warn("login password: not set yet (it will be prompted for and stored encrypted at connect time)")
				}
			}

			tunActive := len(rt.Tun.Routes) > 0 || len(rt.Tun.Bypass) > 0
			if tunActive {
				fmt.Printf("        TUN: iface=%s address=%s mtu=%d\n", rt.Tun.Name, rt.Tun.Address, rt.Tun.MTU)
				fmt.Printf("        Tunnel routes: %s\n", joinOrEmpty(rt.Tun.Routes))
				if len(rt.Tun.Bypass) > 0 {
					fmt.Printf("        Direct routes: %s\n", joinOrEmpty(rt.Tun.Bypass))
				}
				if hasPrivileges() {
					pass("        currently privileged (Linux root / Windows administrator)")
				} else {
					fail("        missing privileges: this tunnel has routes, TUN mode needs Linux root or a Windows administrator")
				}
				if bin, berr := tun2socks.Find(rt); berr != nil {
					fail("        tun2socks binary not found: " + berr.Error())
				} else {
					pass("        tun2socks binary: " + bin)
					if runtime.GOOS == "windows" {
						checkWintun(bin, pass, warn)
					}
				}
				if runtime.GOOS == "linux" {
					if _, serr := os.Stat("/dev/net/tun"); serr != nil {
						fail("        /dev/net/tun does not exist: load the tun module (modprobe tun)")
					} else {
						pass("        /dev/net/tun exists")
					}
				}
			} else {
				warn("no tunnel route is configured, this tunnel only does port forwarding (no TUN is created)")
			}

			fmt.Printf("        Port forwards: %d local, %d remote\n", len(rt.Forwards.Local), len(rt.Forwards.Remote))

			if checkConnect {
				if !t.Enabled {
					continue
				}
				fmt.Printf("        testing the SSH connection of %s ...\n", t.Name)
				cli := sshclient.New(rt)
				if isInteractive() {
					cli.PromptHostKey = interactiveHostKey()
				}
				if cerr := connectWithPassword(rt, cli, dbSaver{st: st, name: t.Name}); cerr != nil {
					fail(fmt.Sprintf("        SSH connection of tunnel %s failed: %v", t.Name, cerr))
					connectErrs = append(connectErrs, fmt.Errorf("tunnel %s: %w", t.Name, cerr))
				} else {
					pass(fmt.Sprintf("        SSH connection of tunnel %s succeeded: %s@%s:%d", t.Name, rt.SSH.User, rt.SSH.Host, rt.SSH.Port))
					// 探测对端是否允许 TCP 转发：被策略拒绝时 SSH 握手正常、隧道却无法承载任何流量。
					if perr := cli.ProbeForwarding(probeForwardTarget); perr != nil {
						fail(fmt.Sprintf("        forwarding channel of tunnel %s is unavailable: %v", t.Name, perr))
						connectErrs = append(connectErrs, fmt.Errorf("tunnel %s: %w", t.Name, perr))
					} else {
						pass(fmt.Sprintf("        forwarding channel of tunnel %s is available (the peer allows TCP forwarding)", t.Name))
					}
				}
				_ = cli.Close()
			}
		}

		if len(connectErrs) > 0 {
			return fmt.Errorf("%d tunnel(s) failed the self-test", len(connectErrs))
		}
		return nil
	},
}

// checkWintun 检查 Windows 下 wintun.dll 是否随 tun2socks 就位。
func checkWintun(bin string, pass, warn func(string)) {
	dir := filepath.Dir(bin)
	if _, err := os.Stat(filepath.Join(dir, "wintun.dll")); err == nil {
		pass("        wintun.dll: " + filepath.Join(dir, "wintun.dll"))
		return
	}
	if _, err := os.Stat("wintun.dll"); err == nil {
		pass("        wintun.dll: ./wintun.dll")
		return
	}
	warn("        wintun.dll not found (next to tun2socks.exe or in the working directory); run `sshtun fetch` to download it")
}

func init() {
	checkCmd.Flags().BoolVar(&checkConnect, "connect", false, "also test the SSH dial and authentication of each tunnel")
}

func joinOrEmpty(list []string) string {
	out := ""
	for i, s := range list {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// filterTunnelsByName 按名称筛选隧道（不限启用状态）；names 为空或含 "all" 时
// 返回全部，并对不存在的名字告警。
func filterTunnelsByName(all []*store.Tunnel, names []string) []*store.Tunnel {
	if isAllNames(names) {
		return all
	}
	byName := make(map[string]*store.Tunnel, len(all))
	for _, t := range all {
		byName[t.Name] = t
	}
	seen := map[string]bool{}
	var out []*store.Tunnel
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		t, ok := byName[n]
		if !ok {
			fmt.Printf("Warning: tunnel %q does not exist, skipping\n", n)
			continue
		}
		out = append(out, t)
	}
	return out
}

// indent 为多行错误信息统一加缩进，便于在 check 输出中对齐。
func indent(s string) string {
	if s == "" {
		return s
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = "         " + lines[i]
	}
	return strings.Join(lines, "\n")
}
