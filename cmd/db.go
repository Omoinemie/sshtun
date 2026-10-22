package cmd

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/secret"
	"github.com/Omoinemie/sshtun/internal/store"
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Manage tunnels, routes and port forwards stored in the database (the config file only holds basic settings)",
	Long: `Tunnels, routes and port forwards are persisted in a SQLite database (see [app] db in the config file).
Use this command group to add, remove, list and modify them; ` + "`sshtun start/stop/restart/status/check`" + ` runs according to the database contents.`,
}

// openDB 依据基础配置打开数据库。
func openDB() (*store.Store, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, err
	}
	return store.Open(cfg.App.DB)
}

/* -------------------------------- tunnel -------------------------------- */

var dbTunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Manage tunnels (SSH + TUN)",
}

var (
	dbTunnelListAll bool
	tunnelAddOpts   tunnelOpts
	tunnelSetOpts   tunnelOpts
	// assumeYes 由 rm 命令的 -y/--yes 设置，用于跳过交互确认。
	assumeYes bool
)

var dbTunnelListCmd = &cobra.Command{
	Use:   "list",
	Short: "List tunnels",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openDB()
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()
		tunnels, err := st.ListTunnels()
		if err != nil {
			return err
		}
		if len(tunnels) == 0 {
			fmt.Println("(no tunnels in the database)")
			return nil
		}
		fmt.Printf("%-20s %-6s %-24s %-16s %-5s %s\n", "NAME", "STATE", "SSH", "TUN", "ROUTES", "FWD")
		for _, t := range tunnels {
			if !dbTunnelListAll && !t.Enabled {
				continue
			}
			state := "off"
			if t.Enabled {
				state = "on"
			}
			ssh := fmt.Sprintf("%s@%s:%d", t.SSHUser, t.SSHHost, t.SSHPort)
			tun := fmt.Sprintf("%s (%s)", t.TunName, t.TunAddress)
			fmt.Printf("%-20s %-6s %-24s %-16s %-5d %d\n",
				t.Name, state, ssh, tun, len(t.Routes), len(t.Forwards))
		}
		return nil
	},
}

var dbTunnelShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show the full configuration of a tunnel",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openDB()
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()
		t, err := st.GetTunnel(args[0])
		if err != nil {
			return err
		}
		state := "off"
		if t.Enabled {
			state = "on"
		}
		fmt.Printf("Tunnel:   %s (%s)\n", t.Name, state)
		fmt.Printf("SSH:      %s@%s:%d  auth=%s\n", t.SSHUser, t.SSHHost, t.SSHPort, t.SSHAuth)
		if t.SSHAuth == "password" {
			pw := "not set"
			if secret.IsEncrypted(t.SSHPassword) {
				pw = "stored encrypted"
			} else if t.SSHPassword != "" {
				pw = "plaintext (ignored at connect time, will be re-entered)"
			}
			fmt.Printf("Password: %s\n", pw)
		}
		if t.SSHKeyFile != "" {
			fmt.Printf("Key file: %s\n", t.SSHKeyFile)
		}
		fmt.Printf("Host key: %s\n", t.SSHHostKey)
		fmt.Printf("TUN:      %s (%s, mtu=%d)\n", t.TunName, t.TunAddress, t.TunMTU)
		if len(t.Routes) == 0 {
			fmt.Println("Routes:   (none)")
		} else {
			fmt.Println("Routes:")
			for _, r := range t.Routes {
				fmt.Printf("  %-8s %s\n", r.Kind, r.CIDR)
			}
		}
		if len(t.Forwards) == 0 {
			fmt.Println("Forwards: (none)")
		} else {
			fmt.Println("Forwards:")
			for i, f := range t.Forwards {
				en := "off"
				if f.Enabled {
					en = "on"
				}
				bind := strconv.Itoa(f.BindPort)
				if f.BindAddr != "" {
					bind = f.BindAddr + ":" + bind
				}
				fmt.Printf("  [%d] %-6s %s -> %s:%d (%s)\n", i, f.Direction, bind, f.TargetHost, f.TargetPort, en)
			}
		}
		return nil
	},
}

var dbTunnelAddCmd = &cobra.Command{
	Use:   "add [name]",
	Short: "Create a tunnel (omit the name to use the wizard in an interactive terminal)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openDB()
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()

		name := ""
		if len(args) == 1 {
			name = strings.TrimSpace(args[0])
		}
		if name != "" {
			if err := ensureTunnelAbsent(st, name); err != nil {
				return err
			}
		}

		// 未指定 --host 时进入向导（仅交互终端）。
		if !cmd.Flags().Changed("host") {
			if !wizardEnabled() {
				return fmt.Errorf("--host is required to specify the SSH server (not an interactive terminal, the wizard is unavailable)")
			}
			existing, lerr := st.ListTunnels()
			if lerr != nil {
				return lerr
			}
			if err := runTunnelAddWizard(cmd, &name, existing); err != nil {
				return err
			}
			if name == "" {
				return fmt.Errorf("tunnel name is required")
			}
			if err := ensureTunnelAbsent(st, name); err != nil {
				return err
			}
		}
		if name == "" {
			return fmt.Errorf("tunnel name is required")
		}
		if err := validateTunnelName(name); err != nil {
			return err
		}

		t := tunnelAddOpts.newTunnel()
		t.Name = name
		if err := tunnelAddOpts.applyChanged(cmd, t); err != nil {
			return err
		}
		if t.SSHHost == "" {
			return fmt.Errorf("--host is required to specify the SSH server")
		}
		if err := st.UpsertTunnel(t); err != nil {
			return err
		}
		fmt.Printf("Added tunnel %s\n", name)
		return nil
	},
}

// ensureTunnelAbsent 校验同名隧道尚不存在。
func ensureTunnelAbsent(st *store.Store, name string) error {
	if _, err := st.GetTunnel(name); err == nil {
		return fmt.Errorf("tunnel %q already exists; use `sshtun db tunnel set %s` to modify it", name, name)
	} else if err != store.ErrNotExist {
		return err
	}
	return nil
}

var dbTunnelSetCmd = &cobra.Command{
	Use:   "set [name]",
	Short: "Update a tunnel (omit the name or the fields to use the wizard; only explicitly given fields are changed)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openDB()
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()

		w := newWizard()
		name := ""
		if len(args) == 1 {
			name = strings.TrimSpace(args[0])
		}
		if name == "" {
			if !wizardEnabled() {
				return fmt.Errorf("tunnel name is required")
			}
			existing, lerr := st.ListTunnels()
			if lerr != nil {
				return lerr
			}
			if name, err = w.pickTunnel(existing, "Select the tunnel to modify: "); err != nil {
				return err
			}
		}

		t, err := st.GetTunnel(name)
		if err != nil {
			return err
		}

		// 未显式指定任何字段时进入向导逐项修改。
		if !tunnelFlagsChanged(cmd) {
			if !wizardEnabled() {
				return fmt.Errorf("no field given; use --host/--port/... or run in an interactive terminal to use the wizard")
			}
			fmt.Printf("Wizard-style edit of tunnel %q (press Enter to keep the current value):\n", name)
			if err := wizardEditTunnel(cmd, w, t); err != nil {
				return err
			}
		}

		if err := tunnelSetOpts.applyChanged(cmd, t); err != nil {
			return err
		}
		if err := st.UpsertTunnel(t); err != nil {
			return err
		}
		fmt.Printf("Updated tunnel %s\n", name)
		return nil
	},
}

// tunnelFlagsChanged 报告是否显式指定了任一隧道字段。
func tunnelFlagsChanged(cmd *cobra.Command) bool {
	for _, n := range []string{"host", "port", "user", "auth", "password", "key-file",
		"key-passphrase", "host-key", "tun-name", "tun-address", "mtu", "disable"} {
		if cmd.Flags().Changed(n) {
			return true
		}
	}
	return false
}

var dbTunnelRmCmd = &cobra.Command{
	Use:     "rm [name]",
	Aliases: []string{"remove", "delete"},
	Short:   "Delete a tunnel (with its routes and forwards; asks for confirmation in an interactive terminal, use -y to skip)",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openDB()
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()

		w := newWizard()
		name := ""
		if len(args) == 1 {
			name = strings.TrimSpace(args[0])
		}
		if name == "" {
			if !wizardEnabled() {
				return fmt.Errorf("tunnel name is required")
			}
			existing, lerr := st.ListTunnels()
			if lerr != nil {
				return lerr
			}
			if name, err = w.pickTunnel(existing, "Select the tunnel to delete: "); err != nil {
				return err
			}
		}
		t, err := st.GetTunnel(name)
		if err != nil {
			return err
		}
		if !assumeYes && wizardEnabled() {
			ok, cerr := confirmTunnelDelete(w, t)
			if cerr != nil {
				return cerr
			}
			if !ok {
				fmt.Println("Cancelled")
				return nil
			}
		}
		if err := st.DeleteTunnel(name); err != nil {
			return err
		}
		fmt.Printf("Deleted tunnel %s\n", name)
		return nil
	},
}

func newTunnelEnableCmd(enable bool) *cobra.Command {
	verb, state := "enable", "Enabled"
	if !enable {
		verb, state = "disable", "Disabled"
	}
	return &cobra.Command{
		Use:   verb + " <name>",
		Short: state + " a tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openDB()
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			if err := st.SetEnabled(args[0], enable); err != nil {
				return err
			}
			fmt.Printf("%s tunnel %s\n", state, args[0])
			return nil
		},
	}
}

/* --------------------------------- route -------------------------------- */

var dbRouteCmd = &cobra.Command{
	Use:   "route",
	Short: "Manage the routes of a tunnel (through the tunnel / forced direct)",
}

var routeBypass bool

var dbRouteAddCmd = &cobra.Command{
	Use:   "add <tunnel> <cidr[,cidr...]>",
	Short: "Add one or more routes to a tunnel (comma-separated CIDRs; --bypass forces direct connection; omit args for the wizard)",
	Args:  cobra.MaximumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		var name, cidrArg string
		if len(args) >= 1 {
			name = strings.TrimSpace(args[0])
		}
		if len(args) >= 2 {
			cidrArg = strings.TrimSpace(args[1])
		}
		if name == "" || cidrArg == "" {
			if !wizardEnabled() {
				return fmt.Errorf("usage: sshtun db route add <tunnel> <cidr[,cidr...]> (omit args to use the wizard in an interactive terminal)")
			}
			st, err := openDB()
			if err != nil {
				return err
			}
			existing, lerr := st.ListTunnels()
			_ = st.Close()
			if lerr != nil {
				return lerr
			}
			w := newWizard()
			if err := runRouteAddWizard(cmd, w, &name, &cidrArg, existing); err != nil {
				return err
			}
		}
		cidrs := SplitCSV(cidrArg)
		if len(cidrs) == 0 {
			return fmt.Errorf("no CIDR given")
		}
		// Validate every CIDR before touching the database, so a bad entry
		// in the list does not leave half of the routes added.
		seen := map[string]bool{}
		for _, c := range cidrs {
			if err := validateCIDROrIP(c); err != nil {
				return err
			}
			if seen[c] {
				return fmt.Errorf("duplicate CIDR %q in the list", c)
			}
			seen[c] = true
		}
		kind := store.RouteKindTunnel
		if routeBypass {
			kind = store.RouteKindBypass
		}
		return mutateTunnel(name, func(t *store.Tunnel) error {
			existing := map[string]bool{}
			for _, r := range t.Routes {
				existing[r.CIDR] = true
			}
			for _, c := range cidrs {
				if existing[c] {
					return fmt.Errorf("tunnel %s already has route %s", name, c)
				}
			}
			for _, c := range cidrs {
				t.Routes = append(t.Routes, store.Route{CIDR: c, Kind: kind})
			}
			return nil
		}, "Added %d route(s) to tunnel %s: %s", len(cidrs), name, strings.Join(cidrs, ", "))
	},
}

var dbRouteRmCmd = &cobra.Command{
	Use:     "rm [tunnel] [cidr]",
	Aliases: []string{"remove", "delete"},
	Short:   "Remove a route from a tunnel (omit the arguments to use the wizard; asks for confirmation in an interactive terminal, use -y to skip)",
	Args:    cobra.MaximumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openDB()
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()

		w := newWizard()
		name := ""
		if len(args) >= 1 {
			name = strings.TrimSpace(args[0])
		}
		cidr := ""
		if len(args) >= 2 {
			cidr = strings.TrimSpace(args[1])
		}
		if name == "" {
			if !wizardEnabled() {
				return fmt.Errorf("tunnel name is required")
			}
			existing, lerr := st.ListTunnels()
			if lerr != nil {
				return lerr
			}
			if name, err = w.pickTunnel(existing, "Select a tunnel: "); err != nil {
				return err
			}
		}
		t, err := st.GetTunnel(name)
		if err != nil {
			return err
		}
		if cidr == "" {
			if !wizardEnabled() {
				return fmt.Errorf("the CIDR to remove is required")
			}
			if cidr, err = pickRouteToDelete(w, t); err != nil {
				return err
			}
		}
		if !assumeYes && wizardEnabled() {
			fmt.Printf("\nAbout to remove route %s from tunnel %s\n", cidr, name)
			ok, cerr := w.confirm("Confirm removal? ", false)
			if cerr != nil {
				return cerr
			}
			if !ok {
				fmt.Println("Cancelled")
				return nil
			}
		}
		return mutateTunnel(name, func(t *store.Tunnel) error {
			kept := t.Routes[:0]
			found := false
			for _, r := range t.Routes {
				if r.CIDR == cidr {
					found = true
					continue
				}
				kept = append(kept, r)
			}
			if !found {
				return fmt.Errorf("tunnel %s has no route %s", name, cidr)
			}
			t.Routes = kept
			return nil
		}, "Removed route %s from tunnel %s", cidr, name)
	},
}

var dbRouteListCmd = &cobra.Command{
	Use:   "list <tunnel>",
	Short: "List the routes of a tunnel",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openDB()
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()
		t, err := st.GetTunnel(args[0])
		if err != nil {
			return err
		}
		if len(t.Routes) == 0 {
			fmt.Println("(no routes)")
			return nil
		}
		for _, r := range t.Routes {
			fmt.Printf("%-8s %s\n", r.Kind, r.CIDR)
		}
		return nil
	},
}

/* -------------------------------- forward ------------------------------- */

var dbForwardCmd = &cobra.Command{
	Use:   "forward",
	Short: "Manage the port forwards of a tunnel (local/-L or remote/-R)",
}

var (
	fwdBindAddr string
	fwdDisabled bool
)

var dbForwardAddCmd = &cobra.Command{
	Use:   "add <tunnel> <local|remote> <bind_port[,bind_port...]> <target_host:target_port[,target...]>",
	Short: "Add one or more port forwards to a tunnel (comma-separated; a single target applies to every port; omit args for the wizard)",
	Args:  cobra.MaximumNArgs(4),
	RunE: func(cmd *cobra.Command, args []string) error {
		var name, dir, bindPortStr, target string
		if len(args) >= 1 {
			name = strings.TrimSpace(args[0])
		}
		if len(args) >= 2 {
			dir = strings.TrimSpace(args[1])
		}
		if len(args) >= 3 {
			bindPortStr = strings.TrimSpace(args[2])
		}
		if len(args) >= 4 {
			target = strings.TrimSpace(args[3])
		}
		if name == "" || dir == "" || bindPortStr == "" || target == "" {
			if !wizardEnabled() {
				return fmt.Errorf("usage: sshtun db forward add <tunnel> <local|remote> <bind_port[,bind_port...]> <target_host:target_port[,target...]> (omit args to use the wizard in an interactive terminal)")
			}
			st, err := openDB()
			if err != nil {
				return err
			}
			existing, lerr := st.ListTunnels()
			_ = st.Close()
			if lerr != nil {
				return lerr
			}
			w := newWizard()
			if err := runForwardAddWizard(cmd, w, &name, &dir, &bindPortStr, &target, existing); err != nil {
				return err
			}
		}
		if dir != store.ForwardLocal && dir != store.ForwardRemote {
			return fmt.Errorf("direction must be local or remote, got: %q", dir)
		}

		// Parse the whole list first: a bad entry must not leave the
		// earlier forwards of the same command already added.
		fws, err := parseForwardSpecs(bindPortStr, target)
		if err != nil {
			return err
		}

		return mutateTunnel(name, func(t *store.Tunnel) error {
			for _, f := range fws {
				t.Forwards = append(t.Forwards, store.Forward{
					Direction:  dir,
					BindAddr:   fwdBindAddr,
					BindPort:   f.port,
					TargetHost: f.host,
					TargetPort: f.tport,
					Enabled:    !fwdDisabled,
				})
			}
			return nil
		}, "Added %d forward(s) to tunnel %s: %s", len(fws), name, describeForwards(fws))
	},
}

// forwardSpec 是一条端口转发的解析结果。
type forwardSpec struct {
	port  int
	host  string
	tport int
}

// parseForwardSpecs 解析「端口列表 + 目标列表」，返回逐条转发的定义。
//
// 端口与目标数量相同时按顺序一一对应；只给一个目标时，该目标被所有端口共用
// （最常见的「同一后端开多个端口」场景）；其余组合视为参数错误。
func parseForwardSpecs(bindPorts, targets string) ([]forwardSpec, error) {
	portStrs := SplitCSV(bindPorts)
	targetStrs := SplitCSV(targets)
	if len(portStrs) == 0 {
		return nil, fmt.Errorf("no bind port given")
	}
	if len(targetStrs) == 0 {
		return nil, fmt.Errorf("no target given")
	}
	if len(portStrs) != len(targetStrs) && len(targetStrs) != 1 {
		return nil, fmt.Errorf("bind port count (%d) and target count (%d) do not match; give one target per port, or a single target for all ports", len(portStrs), len(targetStrs))
	}

	ports := make([]int, 0, len(portStrs))
	for _, p := range portStrs {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid bind port: %q", p)
		}
		ports = append(ports, n)
	}

	tgts := make([]forwardSpec, 0, len(targetStrs))
	for _, t := range targetStrs {
		host, portStr, err := net.SplitHostPort(t)
		if err != nil {
			return nil, fmt.Errorf("target must be in host:port form, got: %q", t)
		}
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid target port: %q", portStr)
		}
		tgts = append(tgts, forwardSpec{host: host, tport: p})
	}

	out := make([]forwardSpec, 0, len(ports))
	for i, port := range ports {
		spec := tgts[0]
		if len(tgts) > 1 {
			spec = tgts[i]
		}
		spec.port = port
		out = append(out, spec)
	}
	return out, nil
}

// describeForwards 把转发列表拼成一行可读文本，用于成功提示。
func describeForwards(fws []forwardSpec) string {
	parts := make([]string, 0, len(fws))
	for _, f := range fws {
		parts = append(parts, fmt.Sprintf("%d->%s:%d", f.port, f.host, f.tport))
	}
	return strings.Join(parts, ", ")
}

var dbForwardRmCmd = &cobra.Command{
	Use:     "rm [tunnel] [local|remote] [bind_port]",
	Aliases: []string{"remove", "delete"},
	Short:   "Remove a port forward from a tunnel (omit the arguments to use the wizard; asks for confirmation in an interactive terminal, use -y to skip)",
	Args:    cobra.MaximumNArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openDB()
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()

		w := newWizard()
		name := ""
		if len(args) >= 1 {
			name = strings.TrimSpace(args[0])
		}
		dir := ""
		if len(args) >= 2 {
			dir = strings.TrimSpace(args[1])
		}
		bindPort := 0
		if len(args) >= 3 {
			n, perr := strconv.Atoi(args[2])
			if perr != nil {
				return fmt.Errorf("invalid bind port: %q", args[2])
			}
			bindPort = n
		}
		if name == "" {
			if !wizardEnabled() {
				return fmt.Errorf("tunnel name is required")
			}
			existing, lerr := st.ListTunnels()
			if lerr != nil {
				return lerr
			}
			if name, err = w.pickTunnel(existing, "Select a tunnel: "); err != nil {
				return err
			}
		}
		t, err := st.GetTunnel(name)
		if err != nil {
			return err
		}
		if dir == "" || bindPort == 0 {
			if !wizardEnabled() {
				return fmt.Errorf("usage: sshtun db forward rm <tunnel> <local|remote> <bind_port>")
			}
			if dir, bindPort, err = pickForwardToDelete(w, t); err != nil {
				return err
			}
		}
		if !assumeYes && wizardEnabled() {
			fmt.Printf("\nAbout to remove forward %s:%d from tunnel %s\n", dir, bindPort, name)
			ok, cerr := w.confirm("Confirm removal? ", false)
			if cerr != nil {
				return cerr
			}
			if !ok {
				fmt.Println("Cancelled")
				return nil
			}
		}
		return mutateTunnel(name, func(t *store.Tunnel) error {
			kept := t.Forwards[:0]
			found := false
			for i := range t.Forwards {
				f := t.Forwards[i]
				if f.Direction == dir && f.BindPort == bindPort {
					found = true
					continue
				}
				kept = append(kept, f)
			}
			if !found {
				return fmt.Errorf("tunnel %s has no %s forward on port %d", name, dir, bindPort)
			}
			t.Forwards = kept
			return nil
		}, "Removed forward %s:%d from tunnel %s", dir, bindPort, name)
	},
}

var dbForwardListCmd = &cobra.Command{
	Use:   "list <tunnel>",
	Short: "List the port forwards of a tunnel",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openDB()
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()
		t, err := st.GetTunnel(args[0])
		if err != nil {
			return err
		}
		if len(t.Forwards) == 0 {
			fmt.Println("(no forwards)")
			return nil
		}
		for _, f := range t.Forwards {
			en := "off"
			if f.Enabled {
				en = "on"
			}
			bind := strconv.Itoa(f.BindPort)
			if f.BindAddr != "" {
				bind = f.BindAddr + ":" + bind
			}
			fmt.Printf("%-6s %s -> %s:%d (%s)\n", f.Direction, bind, f.TargetHost, f.TargetPort, en)
		}
		return nil
	},
}

/* ------------------------------- helpers -------------------------------- */

// mutateTunnel 载入隧道、应用变更并整体写回，成功后打印 msg（msg 为 Printf 格式）。
func mutateTunnel(name string, mutate func(*store.Tunnel) error, msg string, args ...any) error {
	st, err := openDB()
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	t, err := st.GetTunnel(name)
	if err != nil {
		return err
	}
	if err := mutate(t); err != nil {
		return err
	}
	if err := st.UpsertTunnel(t); err != nil {
		return err
	}
	fmt.Printf(msg+"\n", args...)
	return nil
}

// validateCIDROrIP 校验路由为合法网段或 IP。
func validateCIDROrIP(s string) error {
	if strings.Contains(s, "/") {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		return nil
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("invalid IP address %q", s)
	}
	return nil
}

// tunnelOpts 是 tunnel add/set 共用的字段集合。
type tunnelOpts struct {
	host          string
	port          int
	user          string
	auth          string
	password      string
	keyFile       string
	keyPassphrase string
	hostKey       string
	tunName       string
	tunAddress    string
	mtu           int
	disabled      bool
}

// bindTunnelFlags 在命令上注册隧道相关标志并绑定到 o。
func bindTunnelFlags(cmd *cobra.Command, o *tunnelOpts) {
	f := cmd.Flags()
	f.StringVar(&o.host, "host", "", "SSH server address")
	f.IntVar(&o.port, "port", 0, "SSH port (default 22)")
	f.StringVar(&o.user, "user", "", "SSH user name (default root)")
	f.StringVar(&o.auth, "auth", "", "authentication method: password|key (default key)")
	f.StringVar(&o.password, "password", "", "SSH password in plain text (encrypted automatically on write)")
	f.StringVar(&o.keyFile, "key-file", "", "path to the private key file")
	f.StringVar(&o.keyPassphrase, "key-passphrase", "", "private key passphrase")
	f.StringVar(&o.hostKey, "host-key", "", "host key policy: accept-new|strict|none|path to known_hosts (default accept-new)")
	f.StringVar(&o.tunName, "tun-name", "", "TUN interface name")
	f.StringVar(&o.tunAddress, "tun-address", "", "TUN address in CIDR form")
	f.IntVar(&o.mtu, "mtu", 0, "TUN MTU (default 1500)")
	f.BoolVar(&o.disabled, "disable", false, "leave the tunnel disabled after creating/updating it")
}

// newTunnel 返回带默认值的新隧道。
func (o *tunnelOpts) newTunnel() *store.Tunnel {
	return &store.Tunnel{
		Enabled:    true,
		SSHPort:    config.DefaultSSHPort,
		SSHUser:    "root",
		SSHAuth:    "key",
		SSHHostKey: "accept-new",
		TunName:    config.DefaultTunName,
		TunAddress: config.DefaultTunAddress,
		TunMTU:     config.DefaultTunMTU,
	}
}

// applyChanged 仅把用户显式指定的标志覆盖到隧道上（set 为部分更新）。
func (o *tunnelOpts) applyChanged(cmd *cobra.Command, t *store.Tunnel) error {
	ch := cmd.Flags().Changed
	// 连接地址（主机/端口）变化时，已保存的密码立即作废：
	// 密码是发给该地址的凭证，换了地址还沿用旧密码，等于把旧密码送到新地址。
	// 作废后隧道启动时会因缺少密码而失败，需重新输入。
	addrChanged := (ch("host") && o.host != t.SSHHost) || (ch("port") && o.port != t.SSHPort)

	if ch("host") {
		t.SSHHost = o.host
	}
	if ch("port") {
		t.SSHPort = o.port
	}
	if ch("user") {
		t.SSHUser = o.user
	}
	if ch("auth") {
		t.SSHAuth = o.auth
	}
	if addrChanged {
		// 地址变了：旧密码作废（本次若同时给了新密码，则用新密码覆盖）。
		t.SSHPassword = ""
	}
	if ch("password") {
		enc, err := secret.Encrypt(o.password)
		if err != nil {
			return fmt.Errorf("failed to encrypt the password: %w", err)
		}
		t.SSHPassword = enc
	}
	if ch("key-file") {
		t.SSHKeyFile = o.keyFile
	}
	if ch("key-passphrase") {
		t.SSHKeyPassphrase = o.keyPassphrase
	}
	if ch("host-key") {
		t.SSHHostKey = o.hostKey
	}
	if ch("tun-name") {
		t.TunName = o.tunName
	}
	if ch("tun-address") {
		t.TunAddress = o.tunAddress
	}
	if ch("mtu") {
		t.TunMTU = o.mtu
	}
	if ch("disable") {
		t.Enabled = !o.disabled
	}
	return nil
}

func init() {
	dbTunnelListCmd.Flags().BoolVarP(&dbTunnelListAll, "all", "a", false, "also list disabled tunnels")
	dbTunnelCmd.AddCommand(dbTunnelListCmd)
	dbTunnelCmd.AddCommand(dbTunnelShowCmd)
	bindTunnelFlags(dbTunnelAddCmd, &tunnelAddOpts)
	dbTunnelCmd.AddCommand(dbTunnelAddCmd)
	bindTunnelFlags(dbTunnelSetCmd, &tunnelSetOpts)
	dbTunnelCmd.AddCommand(dbTunnelSetCmd)
	dbTunnelRmCmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "skip the interactive confirmation")
	dbTunnelCmd.AddCommand(dbTunnelRmCmd)
	dbTunnelCmd.AddCommand(newTunnelEnableCmd(true))
	dbTunnelCmd.AddCommand(newTunnelEnableCmd(false))
	dbCmd.AddCommand(dbTunnelCmd)

	dbRouteAddCmd.Flags().BoolVar(&routeBypass, "bypass", false, "force a direct connection (default: through the tunnel)")
	dbRouteRmCmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "skip the interactive confirmation")
	dbRouteCmd.AddCommand(dbRouteAddCmd)
	dbRouteCmd.AddCommand(dbRouteRmCmd)
	dbRouteCmd.AddCommand(dbRouteListCmd)
	dbCmd.AddCommand(dbRouteCmd)

	dbForwardAddCmd.Flags().StringVar(&fwdBindAddr, "bind-addr", "", "bind address (local forwards default to 127.0.0.1)")
	dbForwardAddCmd.Flags().BoolVar(&fwdDisabled, "disable", false, "leave the forward disabled after adding it")
	dbForwardRmCmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "skip the interactive confirmation")
	dbForwardCmd.AddCommand(dbForwardAddCmd)
	dbForwardCmd.AddCommand(dbForwardRmCmd)
	dbForwardCmd.AddCommand(dbForwardListCmd)
	dbCmd.AddCommand(dbForwardCmd)

	rootCmd.AddCommand(dbCmd)
}
