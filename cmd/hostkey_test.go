package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/hostkey"
	"github.com/Omoinemie/sshtun/internal/secret"
	"github.com/Omoinemie/sshtun/internal/sshclient"
	"github.com/Omoinemie/sshtun/internal/sshtest"
)

func TestReadConfirm(t *testing.T) {
	key := testKey(t)
	cases := map[string]bool{"yes\n": true, "Y\n": true, " no \n": false, "n\n": false, "\n": false}
	for in, want := range cases {
		got, err := hostKeyPrompter(strings.NewReader(in))(testAddr(), key, hostkey.StatusUnknown)
		if err != nil {
			t.Errorf("%q 读取出错: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q => %v, want %v", in, got, want)
		}
	}
}

// 非交互环境（无输入）必须返回错误而不是挂起。
func TestHostKeyPrompterEOF(t *testing.T) {
	_, err := hostKeyPrompter(strings.NewReader(""))(testAddr(), testKey(t), hostkey.StatusUnknown)
	if err == nil {
		t.Fatal("无输入时应返回错误")
	}
}

// 登录自检：确认信任后应写入 known_hosts，使后台子进程无需再交互。
func TestConnectPasswordWritesKnownHostsOnTrustAccept(t *testing.T) {
	srv := sshtest.Start(t)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	accepted := false
	prompt := func(string, ssh.PublicKey, hostkey.Status) (bool, error) {
		accepted = true
		return true, nil
	}
	cfg := testServerConfig(t, srv, knownHosts)
	cli := sshclient.New(cfg)
	cli.PromptHostKey = prompt
	if err := connectWithPassword(cfg, cli, nil); err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	_ = cli.Close()
	if !accepted {
		t.Fatal("首次连接应触发确认")
	}
	if _, err := os.Stat(knownHosts); err != nil {
		t.Fatalf("确认后应写入 known_hosts: %v", err)
	}

	// 模拟下一次运行：指向同一 known_hosts 重新构造配置，已受信任则不应再触发确认。
	cfg2 := testServerConfig(t, srv, knownHosts)
	accepted = false
	cli2 := sshclient.New(cfg2)
	cli2.PromptHostKey = prompt
	if err := connectWithPassword(cfg2, cli2, nil); err != nil {
		t.Fatalf("二次连接失败: %v", err)
	}
	_ = cli2.Close()
	if accepted {
		t.Fatal("已受信任的主机不应再次确认")
	}
}

// 拒绝信任时登录应失败，且不写入。
func TestConnectPasswordHostKeyRejected(t *testing.T) {
	srv := sshtest.Start(t)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	cfg := testServerConfig(t, srv, knownHosts)

	cli := sshclient.New(cfg)
	cli.PromptHostKey = func(string, ssh.PublicKey, hostkey.Status) (bool, error) { return false, nil }
	err := connectWithPassword(cfg, cli, nil)
	if err == nil {
		t.Fatal("拒绝信任后登录应失败")
	}
	if sshclient.IsAuthError(err) {
		t.Fatalf("不应被判定为认证错误（密码是正确的）: %v", err)
	}
	if _, err := os.Stat(knownHosts); !os.IsNotExist(err) {
		t.Fatalf("拒绝信任后不应写入: %v", err)
	}
}

// testServerConfig 返回指向测试 SSH 服务器、密码正确的运行时单隧道配置。
// hostKey 为 host_key 原始取值：none 或 known_hosts 文件路径。
func testServerConfig(t *testing.T, srv *sshtest.Server, hostKey string) *config.Config {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(srv.Addr)
	port, _ := strconv.Atoi(portStr)
	enc, err := secret.Encrypt("test")
	if err != nil {
		t.Fatalf("加密密码失败: %v", err)
	}
	cfg := &config.Config{Path: filepath.Join(t.TempDir(), "setting.conf")}
	cfg.SSH = config.SSHConfig{
		Host:           host,
		Port:           port,
		User:           "test",
		Auth:           "password",
		Password:       enc,
		HostKey:        hostKey,
		Keepalive:      config.DefaultKeepalive,
		ConnectTimeout: config.DefaultConnTimeout,
	}
	cfg.Tun = config.TunConfig{Enabled: false}
	cfg.ResolveSSHPaths()
	return cfg
}

func testAddr() string { return "203.0.113.10:22" }

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("转换公钥失败: %v", err)
	}
	return key
}
