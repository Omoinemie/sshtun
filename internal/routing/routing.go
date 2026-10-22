// Package routing 负责网卡地址配置与路由添加/删除（平台相关实现见 linux.go / windows.go）。
package routing

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// RouteEntry 描述一条由 sshtun 添加的路由，用于 down 时精确清理。
type RouteEntry struct {
	// CIDR 路由目标网段（含 /32）。
	CIDR string `json:"cidr"`
	// Kind: "tunnel"(指向 TUN) | "protect"(SSH 服务器走原网关) | "bypass"(强制直连)。
	Kind string `json:"kind"`
	// Gateway 下一跳网关（tunnel 为 TUN 地址，protect/bypass 为原网关）。
	Gateway string `json:"gateway,omitempty"`
	// Device 出接口（tunnel 为 TUN 名，protect/bypass 为原接口）。
	Device string `json:"device,omitempty"`
}

const (
	KindTunnel  = "tunnel"
	KindProtect = "protect"
	KindBypass  = "bypass"
)

// LookPath 在 PATH 及常见 sbin 目录中查找命令。
func LookPath(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		p := dir + "/" + name
		if _, err := exec.LookPath(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("command %s not found", name)
}

// ParseGatewayOutput 从 `ip route get <host>` 输出解析 via/dev。
// 典型输出: "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 0"
func ParseGatewayOutput(out string) (gateway, dev string) {
	toks := strings.Fields(out)
	for i, t := range toks {
		if t == "via" && i+1 < len(toks) {
			gateway = toks[i+1]
		}
		if t == "dev" && i+1 < len(toks) {
			dev = toks[i+1]
		}
	}
	return gateway, dev
}

// ParseRoutePrintDefault 从 `route print -4` 输出解析默认网关与接口地址。
// 匹配形如 "0.0.0.0  0.0.0.0  <gateway>  <interface>  <metric>" 的行。
func ParseRoutePrintDefault(out string) (gateway, iface string) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" {
			return f[2], f[3]
		}
	}
	return "", ""
}

// CIDRToIPMask 将 CIDR 拆为 IP 与点分十进制掩码（Windows route add 需要）。
// 注意返回的是网络地址（路由目标语义），主机地址请用 HostIP。
func CIDRToIPMask(cidr string) (ip, mask string, err error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}
	if ip4 := ipnet.IP.To4(); ip4 != nil {
		return ip4.String(), net.IP(ipnet.Mask).String(), nil
	}
	return ipnet.IP.String(), net.IP(ipnet.Mask).String(), nil
}

// HostIP 返回 CIDR 中的主机地址（"198.18.0.1/30" → "198.18.0.1"）。
// net.ParseCIDR 的第二个返回值是网络地址（198.18.0.0），把网络地址配成
// 网卡 IP 正是此前 sshtun0 地址错误的根因，这里统一收口避免再犯。
func HostIP(cidr string) (string, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String(), nil
	}
	return ip.String(), nil
}

// IsIPv4Host 报告 host 是否为 IPv4 字面量。
// 保护路由用 `route add` / `ip route` 添加，两者都只支持 IPv4；
// IPv6 字面量或域名（无法在此判定）返回 false，调用方应跳过保护路由。
func IsIPv4Host(host string) bool {
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(host), "[]"))
	return ip != nil && ip.To4() != nil
}
