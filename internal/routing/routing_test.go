package routing

import "testing"

func TestParseGatewayOutput(t *testing.T) {
	out := "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 0\n"
	gw, dev := ParseGatewayOutput(out)
	if gw != "192.168.1.1" || dev != "eth0" {
		t.Fatalf("ParseGatewayOutput = %q, %q; want 192.168.1.1, eth0", gw, dev)
	}
	// 直连场景（无 via）
	gw, dev = ParseGatewayOutput("10.0.0.5 dev eth1 src 10.0.0.2 uid 0")
	if gw != "" || dev != "eth1" {
		t.Fatalf("直连解析错误: %q, %q", gw, dev)
	}
}

func TestParseRoutePrintDefault(t *testing.T) {
	out := `===========================================================================
Interface List
  1...........................Loopback Pseudo-Interface 1
===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
     192.168.1.100  255.255.255.255         On-link     192.168.1.100    281
`
	gw, iface := ParseRoutePrintDefault(out)
	if gw != "192.168.1.1" || iface != "192.168.1.100" {
		t.Fatalf("ParseRoutePrintDefault = %q, %q", gw, iface)
	}
}

func TestCIDRToIPMask(t *testing.T) {
	cases := []struct {
		cidr, ip, mask string
	}{
		{"10.8.0.0/16", "10.8.0.0", "255.255.0.0"},
		{"0.0.0.0/1", "0.0.0.0", "128.0.0.0"},
		{"128.0.0.0/1", "128.0.0.0", "128.0.0.0"},
		{"192.168.7.10/32", "192.168.7.10", "255.255.255.255"},
	}
	for _, c := range cases {
		ip, mask, err := CIDRToIPMask(c.cidr)
		if err != nil {
			t.Fatalf("%s: %v", c.cidr, err)
		}
		if ip != c.ip || mask != c.mask {
			t.Errorf("%s => %s %s, want %s %s", c.cidr, ip, mask, c.ip, c.mask)
		}
	}
	if _, _, err := CIDRToIPMask("bad"); err == nil {
		t.Error("非法 CIDR 应报错")
	}
}

func TestHostIP(t *testing.T) {
	cases := []struct{ cidr, want string }{
		{"198.18.0.1/30", "198.18.0.1"},
		{"10.8.0.1/16", "10.8.0.1"},
		{"192.168.7.10/32", "192.168.7.10"},
		{"fd00::1/64", "fd00::1"},
	}
	for _, c := range cases {
		got, err := HostIP(c.cidr)
		if err != nil {
			t.Fatalf("%s: %v", c.cidr, err)
		}
		if got != c.want {
			t.Errorf("HostIP(%s) = %s, want %s（网络地址当主机地址用是历史 bug）", c.cidr, got, c.want)
		}
	}
	if _, err := HostIP("bad"); err == nil {
		t.Error("非法 CIDR 应报错")
	}
}

// 保护路由只能用 IPv4 添加：IPv6 对端或域名必须识别为「非 IPv4」，
// 从而跳过保护路由而不是让整个 Setup 失败。
func TestIsIPv4Host(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"27.12.36.125", true},
		{"192.168.11.254", true},
		{"", false},
		{"rt.vomiku.com", false},
		{"2001:db8::1", false},
		{"[2001:db8::1]", false},
		{"::1", false},
		{"fd00::1", false},
	}
	for _, c := range cases {
		if got := IsIPv4Host(c.host); got != c.want {
			t.Errorf("IsIPv4Host(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestDeviceArg(t *testing.T) {
	// 编译期平台决定行为，这里只确认不 panic 且非空
	if DeviceArg("sshtun0") == "" {
		t.Fatal("DeviceArg 不应为空")
	}
}
