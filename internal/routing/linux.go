//go:build linux

package routing

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/logging"
)

// DeviceArg 返回传给 tun2socks 的 -device 参数（Linux 需要 tun:// 前缀）。
func DeviceArg(name string) string { return "tun://" + name }

// Setup 配置 TUN 地址并添加路由，返回已添加的路由列表。
// 调用前提：tun2socks 已启动并创建了 TUN 设备。
func Setup(cfg *config.Config, sshHost string) ([]RouteEntry, error) {
	ipCmd, err := LookPath("ip")
	if err != nil {
		return nil, err
	}
	iface := cfg.Tun.Name
	// 注意取主机地址（198.18.0.1）而非网络地址（198.18.0.0）
	tunIP, err := HostIP(cfg.Tun.Address)
	if err != nil {
		return nil, fmt.Errorf("invalid TUN address %q: %w", cfg.Tun.Address, err)
	}

	var entries []RouteEntry
	rollback := func(setupErr error) ([]RouteEntry, error) {
		Teardown(entries, iface)
		return nil, setupErr
	}

	// 1. 快照 SSH 服务器当前路由，用于生成保护路由
	out, err := run(ipCmd, "route", "get", sshHost)
	if err != nil {
		return nil, fmt.Errorf("failed to probe the route to the SSH server: %w (%s)", err, strings.TrimSpace(out))
	}
	origGW, origDev := ParseGatewayOutput(out)
	if origDev == "" {
		return nil, fmt.Errorf("cannot parse the outgoing interface of the SSH server: %q", strings.TrimSpace(out))
	}

	// 2. 等待 TUN 设备出现并配置地址/UP
	if err := waitDevice(ipCmd, iface, 10*time.Second); err != nil {
		return rollback(err)
	}
	if aout, aerr := run(ipCmd, "addr", "add", cfg.Tun.Address, "dev", iface); aerr != nil {
		// 已存在则容忍（残留场景）：必须检查本次命令的输出，而不是前面路由探测的结果。
		if !strings.Contains(strings.ToLower(aout+aerr.Error()), "exists") {
			return rollback(fmt.Errorf("failed to configure the TUN address: %w: %s", aerr, strings.TrimSpace(aout)))
		}
	}
	if _, err := run(ipCmd, "link", "set", iface, "up"); err != nil {
		return rollback(fmt.Errorf("failed to bring up the TUN interface: %w", err))
	}

	// 3. 保护路由：SSH 服务器流量走原网关，避免被隧道路由吞掉。
	// 仅 IPv4 对端可加（`ip route` 默认 inet，IPv6 需 `ip -6 route`）；对端为 IPv6
	// 或非字面量时跳过：当前隧道路由均为 IPv4，IPv6 的 SSH 连接不会受影响。
	if IsIPv4Host(sshHost) {
		protect := RouteEntry{CIDR: sshHost + "/32", Kind: KindProtect, Gateway: origGW, Device: origDev}
		args := []string{"route", "replace", protect.CIDR}
		if origGW != "" {
			args = append(args, "via", origGW)
		}
		args = append(args, "dev", origDev)
		if out, err := run(ipCmd, args...); err != nil {
			logging.Warn("failed to add the SSH protect route, skipping it (if the tunnel routes cover the SSH server address, the connection will be swallowed by the tunnel itself)",
				"host", sshHost, "err", err, "out", strings.TrimSpace(out))
		} else {
			entries = append(entries, protect)
			logging.Info("route", "cidr", protect.CIDR, "gateway", origGW, "dev", origDev, "kind", "protect")
		}
	} else {
		logging.Warn("the SSH peer is not IPv4, skipping the protect route (all tunnel routes are IPv4, no protection needed)", "host", sshHost)
	}

	// 4. bypass 路由（强制直连）
	for _, b := range cfg.NormalizeBypass() {
		e := RouteEntry{CIDR: b, Kind: KindBypass, Gateway: origGW, Device: origDev}
		args := []string{"route", "replace", b}
		if origGW != "" {
			args = append(args, "via", origGW)
		}
		args = append(args, "dev", origDev)
		if _, err := run(ipCmd, args...); err != nil {
			return rollback(fmt.Errorf("failed to add bypass route %s: %w", b, err))
		}
		entries = append(entries, e)
		logging.Info("route", "cidr", b, "gateway", origGW, "dev", origDev, "kind", "bypass")
	}

	// 5. 隧道路由
	for _, r := range cfg.NormalizeRoutes() {
		e := RouteEntry{CIDR: r, Kind: KindTunnel, Gateway: tunIP, Device: iface}
		if _, err := run(ipCmd, "route", "replace", r, "dev", iface); err != nil {
			return rollback(fmt.Errorf("failed to add tunnel route %s: %w", r, err))
		}
		entries = append(entries, e)
		logging.Info("route", "cidr", r, "dev", iface)
	}
	return entries, nil
}

// Teardown 删除 Setup 添加的路由（幂等）。
func Teardown(entries []RouteEntry, iface string) {
	ipCmd, err := LookPath("ip")
	if err != nil {
		logging.Error("failed to clean up the routes", "err", err)
		return
	}
	for _, e := range entries {
		args := []string{"route", "del", e.CIDR}
		if e.Device != "" {
			args = append(args, "dev", e.Device)
		}
		if _, err := run(ipCmd, args...); err != nil {
			logging.Debug("failed to delete the route (ignored)", "cidr", e.CIDR, "err", err)
		}
	}
	// TUN 接口随 tun2socks 退出消失，这里不再删除设备
}

func waitDevice(ipCmd, iface string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if out, err := run(ipCmd, "link", "show", iface); err == nil && strings.TrimSpace(out) != "" {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for the TUN device %s", iface)
}

// WaitGone 等待 TUN 设备消失：重启场景下旧设备需先释放。
// 返回是否已在超时内消失（超时仅告警，不视为错误）。
func WaitGone(iface string, timeout time.Duration) bool {
	ipCmd, err := LookPath("ip")
	if err != nil {
		return true
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := run(ipCmd, "link", "show", iface)
		if err != nil || strings.TrimSpace(out) == "" {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
