//go:build windows

package routing

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/logging"
)

// DeviceArg 返回传给 tun2socks 的 -device 参数（Windows 为 wintun 适配器名）。
func DeviceArg(name string) string { return name }

// Setup 配置 TUN 适配器地址并添加路由。
// 调用前提：tun2socks 已启动并创建了 wintun 适配器（需管理员权限）。
func Setup(cfg *config.Config, sshHost string) ([]RouteEntry, error) {
	iface := cfg.Tun.Name
	// 注意取主机地址（198.18.0.1）而非网络地址（198.18.0.0）
	tunIP, err := HostIP(cfg.Tun.Address)
	if err != nil {
		return nil, fmt.Errorf("invalid TUN address %q: %w", cfg.Tun.Address, err)
	}
	_, tunMask, err := CIDRToIPMask(cfg.Tun.Address)
	if err != nil {
		return nil, fmt.Errorf("invalid TUN address %q: %w", cfg.Tun.Address, err)
	}

	var entries []RouteEntry
	rollback := func(setupErr error) ([]RouteEntry, error) {
		Teardown(entries, iface)
		return nil, setupErr
	}

	// 1. 快照原默认网关（用于 SSH 保护路由）
	out, err := run("route", "print", "-4")
	if err != nil {
		return nil, fmt.Errorf("failed to read the routing table: %w", err)
	}
	origGW, _ := ParseRoutePrintDefault(out)
	if origGW == "" {
		return nil, fmt.Errorf("default gateway not found, cannot generate the SSH protect route")
	}

	// 2. 等待 wintun 适配器出现并配置地址
	if err := waitAdapter(iface, 10*time.Second); err != nil {
		return rollback(err)
	}
	if out, err := run("netsh", "interface", "ip", "set", "address",
		ifNameArg(iface), "source=static", "addr="+tunIP, "mask="+tunMask); err != nil {
		return rollback(fmt.Errorf("failed to configure the adapter address: %w: %s", err, strings.TrimSpace(out)))
	}

	// 3. SSH 保护路由：走原默认网关，避免 SSH 自身流量被隧道路由吞掉。
	// 仅 IPv4 对端可加（Windows route 是 IPv4 专用）；对端为 IPv6 或非字面量时跳过：
	// 当前隧道路由均为 IPv4，IPv6 的 SSH 连接不会受影响，不该因此阻断启动。
	if IsIPv4Host(sshHost) {
		protect := RouteEntry{CIDR: sshHost + "/32", Kind: KindProtect, Gateway: origGW}
		if out, err := run("route", "add", sshHost, "mask", "255.255.255.255", origGW, "metric", "1"); err != nil {
			logging.Warn("failed to add the SSH protect route, skipping it (if the tunnel routes cover the SSH server address, the connection will be swallowed by the tunnel itself)",
				"host", sshHost, "err", err, "out", strings.TrimSpace(out))
		} else {
			entries = append(entries, protect)
			logging.Info("route", "cidr", protect.CIDR, "gateway", origGW, "kind", "protect")
		}
	} else {
		logging.Warn("the SSH peer is not IPv4, skipping the protect route (all tunnel routes are IPv4, no protection needed)", "host", sshHost)
	}

	// 4. bypass 路由
	for _, b := range cfg.NormalizeBypass() {
		cidrIP, cidrMask, err := CIDRToIPMask(b)
		if err != nil {
			return rollback(err)
		}
		e := RouteEntry{CIDR: b, Kind: KindBypass, Gateway: origGW}
		if out, err := run("route", "add", cidrIP, "mask", cidrMask, origGW, "metric", "1"); err != nil {
			return rollback(fmt.Errorf("failed to add bypass route %s: %w: %s", b, err, strings.TrimSpace(out)))
		}
		entries = append(entries, e)
		logging.Info("route", "cidr", b, "gateway", origGW, "kind", "bypass")
	}

	// 5. 隧道路由：必须显式绑定到 TUN 接口。
	// 只给网关时，若网关恰是适配器自身地址，Windows 会回落到默认路由所在的接口
	// （此前观测到接口被写成 WLAN 的 192.168.10.35，导致分流完全失效），
	// 因此这里用 netsh 按接口名添加，明确下一跳与出接口。
	for _, r := range cfg.NormalizeRoutes() {
		e := RouteEntry{CIDR: r, Kind: KindTunnel, Gateway: tunIP, Device: iface}
		// 幂等：残留的同目标路由先删（忽略不存在的情况）
		_, _ = run("netsh", "interface", "ipv4", "delete", "route", r, iface)
		if out, err := run("netsh", "interface", "ipv4", "add", "route",
			r, iface, tunIP, "metric=1", "store=active"); err != nil {
			return rollback(fmt.Errorf("failed to add tunnel route %s: %w: %s", r, err, strings.TrimSpace(out)))
		}
		entries = append(entries, e)
		logging.Info("route", "cidr", r, "iface", iface, "gateway", tunIP, "kind", "tunnel")
	}
	return entries, nil
}

// Teardown 删除 Setup 添加的路由（幂等）。
func Teardown(entries []RouteEntry, iface string) {
	for _, e := range entries {
		cidrIP, _, err := CIDRToIPMask(e.CIDR)
		if err != nil {
			cidrIP = e.CIDR
		}
		if _, err := run("route", "delete", cidrIP); err != nil {
			logging.Debug("failed to delete the route (ignored)", "cidr", e.CIDR, "err", err)
		}
	}
}

func waitAdapter(iface string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// 精确匹配网卡名即可：netsh 会回显该接口名。
		// 不再用英文 "connected" 兜底——中文 Windows 状态列为「已连接」，兜底判据不成立。
		out, err := run("netsh", "interface", "show", "interface", ifNameArg(iface))
		if err == nil && strings.Contains(out, iface) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for the wintun adapter %s (make sure tun2socks has started and wintun.dll exists)", iface)
}

// ifNameArg 构造 netsh 的 name= 参数：接口名含空白时按 netsh 语法给值加双引号，
// 否则保持裸值。独立参数形式的接口名由 exec 自动加引号（见 run），无需在此处理。
func ifNameArg(name string) string {
	if strings.ContainsAny(name, " \t") {
		return `name="` + name + `"`
	}
	return "name=" + name
}

// WaitGone 等待 wintun 适配器消失：重启场景下旧适配器需先释放，
// 同名新适配器才能创建成功。返回是否已在超时内消失（超时仅告警，不视为错误）。
func WaitGone(iface string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := run("netsh", "interface", "show", "interface", ifNameArg(iface))
		if err != nil || !strings.Contains(out, iface) {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	// 后台模式（sshtun start -d）的守护进程没有控制台，route/netsh 若新建控制台
	// 会闪现黑色小窗；CREATE_NO_WINDOW 让它们静默执行（输出仍由 CombinedOutput 收集）。
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
