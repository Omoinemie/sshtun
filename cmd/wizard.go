package cmd

// 向导式（交互式）配置：当 db 的 add/set/rm 缺参且标准输入为终端时，
// 按提示逐项采集参数；非交互环境（管道/CI/后台子进程）不会进入向导，
// 仍走原有命令行 flag 方式，保持脚本兼容。

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/store"
)

// wizardEnabled 报告是否应进入向导：标准输入是终端，且非后台守护子进程。
func wizardEnabled() bool {
	return isInteractive() && term.IsTerminal(int(os.Stdin.Fd()))
}

// setFlag 设置命令上的标志（同时标记 Changed，供 applyChanged 识别）。
func setFlag(cmd *cobra.Command, name, value string) error {
	return cmd.Flags().Set(name, value)
}

type wizard struct{ in *bufio.Reader }

func newWizard() *wizard { return &wizard{in: bufio.NewReader(os.Stdin)} }

// line 读取一行并去掉首尾空白。
func (w *wizard) line() (string, error) {
	s, err := w.in.ReadString('\n')
	if err != nil && s == "" {
		return "", fmt.Errorf("failed to read the input (this may be a non-interactive session): %w", err)
	}
	return strings.TrimSpace(s), nil
}

// askString 采集字符串；def 非空时回车采用 def；allowEmpty=false 时要求非空。
func (w *wizard) askString(label, def string, allowEmpty bool) (string, error) {
	for {
		if def != "" {
			fmt.Printf("%s [%s]: ", label, def)
		} else {
			fmt.Printf("%s: ", label)
		}
		s, err := w.line()
		if err != nil {
			return "", err
		}
		switch {
		case s != "":
			return s, nil
		case def != "":
			return def, nil
		case allowEmpty:
			return "", nil
		default:
			fmt.Println("  this value must not be empty, please try again")
		}
	}
}

// askInt 采集整数，回车采用 def；取值须落在 [min,max]（def 越界时不允许直接回车）。
func (w *wizard) askInt(label string, def, min, max int) (int, error) {
	for {
		fmt.Printf("%s [%d]: ", label, def)
		s, err := w.line()
		if err != nil {
			return 0, err
		}
		if s == "" {
			if def >= min && def <= max {
				return def, nil
			}
			fmt.Printf("  please enter an integer between %d and %d\n", min, max)
			continue
		}
		n, perr := strconv.Atoi(s)
		if perr != nil || n < min || n > max {
			fmt.Printf("  please enter an integer between %d and %d\n", min, max)
			continue
		}
		return n, nil
	}
}

// askChoice 单选，返回所选下标；回车采用 def。
func (w *wizard) askChoice(label string, options []string, def int) (int, error) {
	fmt.Println(label)
	for i, o := range options {
		mark := " "
		if i == def {
			mark = "*"
		}
		fmt.Printf("  %s %d) %s\n", mark, i+1, o)
	}
	for {
		fmt.Printf("choose [%d]: ", def+1)
		s, err := w.line()
		if err != nil {
			return 0, err
		}
		if s == "" {
			return def, nil
		}
		n, perr := strconv.Atoi(s)
		if perr != nil || n < 1 || n > len(options) {
			fmt.Printf("  please enter a number between 1 and %d\n", len(options))
			continue
		}
		return n - 1, nil
	}
}

// askIndex 从给定条目中单选，返回所选下标。
func (w *wizard) askIndex(label string, items []string) (int, error) {
	if len(items) == 0 {
		return -1, fmt.Errorf("there is nothing to choose from")
	}
	fmt.Println(label)
	for i, s := range items {
		fmt.Printf("  %d) %s\n", i+1, s)
	}
	for {
		fmt.Print("choose a number: ")
		s, err := w.line()
		if err != nil {
			return -1, err
		}
		n, perr := strconv.Atoi(s)
		if perr != nil || n < 1 || n > len(items) {
			fmt.Printf("  please enter a number between 1 and %d\n", len(items))
			continue
		}
		return n - 1, nil
	}
}

// confirm 是/否确认；回车采用 def。
func (w *wizard) confirm(label string, def bool) (bool, error) {
	d := "y/N"
	if def {
		d = "Y/n"
	}
	for {
		fmt.Printf("%s [%s]: ", label, d)
		s, err := w.line()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(s) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Println("  please enter y or n")
		}
	}
}

// askBool 提示 yes/no 问题。
func (w *wizard) askBool(label string, def bool) (bool, error) { return w.confirm(label, def) }

// askSecret 不回显读取敏感值；回车返回空串。
func (w *wizard) askSecret(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	fmt.Printf("%s (not echoed, press Enter to skip): ", label)
	b, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("failed to read the value: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// pickTunnel 列出隧道供选择，返回所选隧道名。
func (w *wizard) pickTunnel(tunnels []*store.Tunnel, label string) (string, error) {
	if len(tunnels) == 0 {
		return "", errNoTunnels
	}
	items := make([]string, len(tunnels))
	for i, t := range tunnels {
		items[i] = fmt.Sprintf("%s %s  %s@%s:%d  TUN %s (%s)",
			t.Name, enabledMark(t.Enabled), t.SSHUser, t.SSHHost, t.SSHPort, t.TunName, t.TunAddress)
	}
	idx, err := w.askIndex(label, items)
	if err != nil {
		return "", err
	}
	return tunnels[idx].Name, nil
}

func enabledMark(b bool) string {
	if b {
		return "(enabled)"
	}
	return "(disabled)"
}

func forwardLabel(f store.Forward) string {
	bind := strconv.Itoa(f.BindPort)
	if f.BindAddr != "" {
		bind = f.BindAddr + ":" + bind
	}
	return fmt.Sprintf("%-6s %s -> %s:%d %s", f.Direction, bind, f.TargetHost, f.TargetPort, enabledMark(f.Enabled))
}

/* ------------------------------ tunnel 向导 ------------------------------ */

// runTunnelAddWizard 交互式新增：先询问隧道名（若未提供），再采集全部字段。
func runTunnelAddWizard(cmd *cobra.Command, name *string, existing []*store.Tunnel) error {
	w := newWizard()
	if *name == "" {
		n, err := w.askString("Tunnel name (a unique identifier, may contain Chinese)", "", false)
		if err != nil {
			return err
		}
		*name = n
	}
	cur := &store.Tunnel{
		Enabled:    true,
		SSHPort:    config.DefaultSSHPort,
		SSHUser:    "root",
		SSHAuth:    "key",
		SSHHostKey: "accept-new",
		TunMTU:     config.DefaultTunMTU,
	}
	cur.TunName, cur.TunAddress = nextFreeTunDefaults(existing)
	fmt.Printf("\nWizard-style creation of tunnel %q:\n", *name)
	return wizardEditTunnel(cmd, w, cur)
}

// wizardEditTunnel 逐项采集隧道字段并写入 cmd 标志；cur 提供当前值/默认值。
func wizardEditTunnel(cmd *cobra.Command, w *wizard, cur *store.Tunnel) error {
	fmt.Println("Press Enter to accept the default/current value shown in [brackets].")

	host, err := w.askString("SSH server address", cur.SSHHost, false)
	if err != nil {
		return err
	}
	if err := setFlag(cmd, "host", host); err != nil {
		return err
	}

	port, err := w.askInt("SSH port", defInt(cur.SSHPort, config.DefaultSSHPort), 1, 65535)
	if err != nil {
		return err
	}
	if err := setFlag(cmd, "port", strconv.Itoa(port)); err != nil {
		return err
	}

	user, err := w.askString("SSH user name", defStr(cur.SSHUser, "root"), false)
	if err != nil {
		return err
	}
	if err := setFlag(cmd, "user", user); err != nil {
		return err
	}

	authOpts := []string{"key (public/private key)", "password (password)"}
	ai := 0
	if cur.SSHAuth == "password" {
		ai = 1
	}
	if ai, err = w.askChoice("Authentication method", authOpts, ai); err != nil {
		return err
	}
	auth := "key"
	if ai == 1 {
		auth = "password"
	}
	if err := setFlag(cmd, "auth", auth); err != nil {
		return err
	}

	if auth == "password" {
		pwd, perr := w.askSecret("SSH login password")
		if perr != nil {
			return perr
		}
		if pwd != "" {
			if err := setFlag(cmd, "password", pwd); err != nil {
				return err
			}
		}
	} else {
		kf, kerr := w.askString("Path to the private key file", cur.SSHKeyFile, false)
		if kerr != nil {
			return kerr
		}
		if err := setFlag(cmd, "key-file", kf); err != nil {
			return err
		}
		kp, kperr := w.askString("Private key passphrase (may be empty)", cur.SSHKeyPassphrase, true)
		if kperr != nil {
			return kperr
		}
		if err := setFlag(cmd, "key-passphrase", kp); err != nil {
			return err
		}
	}

	hkOpts := []string{"accept-new (trust it automatically the first time, then check for changes)", "strict (it must be trusted already, unknown hosts are rejected)", "custom known_hosts file path"}
	hi := 0
	switch cur.SSHHostKey {
	case "", "none", "accept-new":
		hi = 0
	case "ask", "strict":
		hi = 1
	default:
		hi = 2
	}
	if hi, err = w.askChoice("Host key verification", hkOpts, hi); err != nil {
		return err
	}
	switch hi {
	case 0:
		if err := setFlag(cmd, "host-key", "accept-new"); err != nil {
			return err
		}
	case 1:
		if err := setFlag(cmd, "host-key", "strict"); err != nil {
			return err
		}
	default:
		def := cur.SSHHostKey
		if def == "none" || def == "ask" || def == "accept-new" || def == "strict" {
			def = ""
		}
		p, herr := w.askString("Path to the known_hosts file", def, false)
		if herr != nil {
			return herr
		}
		if err := setFlag(cmd, "host-key", p); err != nil {
			return err
		}
	}

	tunName, err := w.askString("TUN interface name", cur.TunName, false)
	if err != nil {
		return err
	}
	if err := setFlag(cmd, "tun-name", tunName); err != nil {
		return err
	}
	tunAddr, err := w.askString("TUN address in CIDR form", cur.TunAddress, false)
	if err != nil {
		return err
	}
	if err := setFlag(cmd, "tun-address", tunAddr); err != nil {
		return err
	}
	mtu, err := w.askInt("TUN MTU", defInt(cur.TunMTU, config.DefaultTunMTU), 576, 65535)
	if err != nil {
		return err
	}
	if err := setFlag(cmd, "mtu", strconv.Itoa(mtu)); err != nil {
		return err
	}
	enabled, err := w.askBool("Enable this tunnel", cur.Enabled)
	if err != nil {
		return err
	}
	return setFlag(cmd, "disable", strconv.FormatBool(!enabled))
}

// confirmTunnelDelete 展示待删除隧道摘要并二次确认。
func confirmTunnelDelete(w *wizard, t *store.Tunnel) (bool, error) {
	fmt.Printf("\nAbout to delete tunnel %s (with %d route(s) and %d forward(s)):\n", t.Name, len(t.Routes), len(t.Forwards))
	fmt.Printf("  SSH: %s@%s:%d  TUN: %s (%s)\n", t.SSHUser, t.SSHHost, t.SSHPort, t.TunName, t.TunAddress)
	return w.confirm("Confirm deletion? ", false)
}

// nextFreeTunDefaults 返回未被占用的最小 TUN 名与地址（sshtun0/1/... 配 198.18.N.1/30）。
func nextFreeTunDefaults(tunnels []*store.Tunnel) (name, addr string) {
	used := map[string]bool{}
	for _, t := range tunnels {
		used[t.TunName] = true
	}
	for i := 0; i < 256; i++ {
		n := fmt.Sprintf("sshtun%d", i)
		if !used[n] {
			return n, fmt.Sprintf("198.18.%d.1/30", i)
		}
	}
	return config.DefaultTunName, config.DefaultTunAddress
}

/* ------------------------------- route 向导 ------------------------------ */

// runRouteAddWizard 交互式采集路由归属隧道、网段与类型。
func runRouteAddWizard(cmd *cobra.Command, w *wizard, name, cidr *string, existing []*store.Tunnel) error {
	if *name == "" {
		n, err := w.pickTunnel(existing, "Select a tunnel: ")
		if err != nil {
			return err
		}
		*name = n
	}
	if *cidr == "" {
		for {
			s, err := w.askString("Route CIDR or IP (e.g. 10.0.0.0/8, 192.168.1.10)", "", false)
			if err != nil {
				return err
			}
			if verr := validateCIDROrIP(s); verr != nil {
				fmt.Printf("  %v\n", verr)
				continue
			}
			*cidr = s
			break
		}
	}
	ci, err := w.askChoice("Route type", []string{"through the tunnel (out via SSH)", "forced direct (bypass, via the original gateway)"}, boolIdx(routeBypass))
	if err != nil {
		return err
	}
	return setFlag(cmd, "bypass", strconv.FormatBool(ci == 1))
}

// pickRouteToDelete 列出隧道路由供选择。
func pickRouteToDelete(w *wizard, t *store.Tunnel) (string, error) {
	if len(t.Routes) == 0 {
		return "", fmt.Errorf("tunnel %s has no route to remove", t.Name)
	}
	items := make([]string, len(t.Routes))
	for i, r := range t.Routes {
		items[i] = fmt.Sprintf("%-8s %s", r.Kind, r.CIDR)
	}
	idx, err := w.askIndex("Select the route to remove: ", items)
	if err != nil {
		return "", err
	}
	return t.Routes[idx].CIDR, nil
}

/* ------------------------------ forward 向导 ----------------------------- */

// runForwardAddWizard 交互式采集转发的归属隧道、方向、端口与目标。
func runForwardAddWizard(cmd *cobra.Command, w *wizard, name, dir, bindPortS, target *string, existing []*store.Tunnel) error {
	if *name == "" {
		n, err := w.pickTunnel(existing, "Select a tunnel: ")
		if err != nil {
			return err
		}
		*name = n
	}
	if *dir == "" {
		di, err := w.askChoice("Forward direction", []string{"local (local port -> remote target, -L)", "remote (remote port -> local target, -R)"}, 0)
		if err != nil {
			return err
		}
		if di == 0 {
			*dir = store.ForwardLocal
		} else {
			*dir = store.ForwardRemote
		}
	}
	if *bindPortS == "" {
		p, err := w.askInt("Bind port", 0, 1, 65535)
		if err != nil {
			return err
		}
		*bindPortS = strconv.Itoa(p)
	}
	if *target == "" {
		th, err := w.askString("Target host", "127.0.0.1", false)
		if err != nil {
			return err
		}
		tp, err := w.askInt("Target port", 0, 1, 65535)
		if err != nil {
			return err
		}
		*target = net.JoinHostPort(th, strconv.Itoa(tp))
	}
	ba, err := w.askString("Bind address (may be empty, defaults to 127.0.0.1)", fwdBindAddr, true)
	if err != nil {
		return err
	}
	if err := setFlag(cmd, "bind-addr", ba); err != nil {
		return err
	}
	en, err := w.askBool("Enable this forward", true)
	if err != nil {
		return err
	}
	return setFlag(cmd, "disable", strconv.FormatBool(!en))
}

// pickForwardToDelete 列出隧道转发供选择，返回方向与监听端口。
func pickForwardToDelete(w *wizard, t *store.Tunnel) (string, int, error) {
	if len(t.Forwards) == 0 {
		return "", 0, fmt.Errorf("tunnel %s has no forward to remove", t.Name)
	}
	items := make([]string, len(t.Forwards))
	for i, f := range t.Forwards {
		items[i] = forwardLabel(f)
	}
	idx, err := w.askIndex("Select the forward to remove: ", items)
	if err != nil {
		return "", 0, err
	}
	return t.Forwards[idx].Direction, t.Forwards[idx].BindPort, nil
}

/* -------------------------------- helpers -------------------------------- */

func defInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func defStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func boolIdx(b bool) int {
	if b {
		return 1
	}
	return 0
}
