package sshclient

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/hostkey"
	"github.com/Omoinemie/sshtun/internal/sshtest"
)

func cfgFor(t *testing.T, sshAddr, password string) *config.Config {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(sshAddr)
	port, _ := strconv.Atoi(portStr)
	return &config.Config{
		Path: t.TempDir() + "/setting.conf",
		SSH: config.SSHConfig{
			Host: host, Port: port, User: "test",
			Auth: "password", Password: password,
			HostKey: "none", Keepalive: 0, ConnectTimeout: 5,
		},
	}
}

// 认证被服务端拒绝与网络层失败必须区分开（决定是否需要重新提示密码）。
func TestIsAuthError(t *testing.T) {
	if IsAuthError(nil) {
		t.Fatal("nil 不应被判为认证错误")
	}
	authErr := errors.New("SSH 握手/认证失败: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain")
	if !IsAuthError(authErr) {
		t.Fatalf("认证被拒应被识别: %v", authErr)
	}
	if IsAuthError(errors.New("连接 127.0.0.1:1 失败: dial tcp 127.0.0.1:1: connect: connection refused")) {
		t.Fatal("拨号失败不应被判为认证错误")
	}
}

// 密码错误时 Connect 返回的错误应可被 IsAuthError 识别。
func TestConnectWrongPasswordIsAuthError(t *testing.T) {
	srv := sshtest.Start(t)
	cli := New(cfgFor(t, srv.Addr, "wrong"))
	err := cli.Connect()
	if err == nil {
		t.Fatal("密码错误时应连接失败")
	}
	if !IsAuthError(err) {
		t.Fatalf("应为认证错误: %v", err)
	}
}

func TestConnectAndDial(t *testing.T) {
	srv := sshtest.Start(t)
	cli := New(cfgFor(t, srv.Addr, "test"))
	if err := cli.Connect(); err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer cli.Close()

	// 隧道拨号：目标为测试 SSH 服务器自身端口（服务端会 net.Dial 回来）
	conn, err := cli.Dial("tcp", srv.Addr)
	if err != nil {
		t.Fatalf("Dial 失败: %v", err)
	}
	_ = conn.Close()
}

func TestAuthFailure(t *testing.T) {
	srv := sshtest.Start(t)
	cli := New(cfgFor(t, srv.Addr, "wrong"))
	if err := cli.Connect(); err == nil {
		_ = cli.Close()
		t.Fatal("错误密码应当认证失败")
	}
}

// TestHostKeyPromptAccepted 验证首次连接会询问，确认后写入信任存储且后续不再询问。
func TestHostKeyPromptAccepted(t *testing.T) {
	srv := sshtest.Start(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	cfg := cfgFor(t, srv.Addr, "test")
	cfg.SSH.HostKey = path

	cli := New(cfg)
	var statuses []hostkey.Status
	cli.PromptHostKey = func(addr string, key ssh.PublicKey, st hostkey.Status) (bool, error) {
		statuses = append(statuses, st)
		return true, nil
	}
	if err := cli.Connect(); err != nil {
		t.Fatalf("确认后连接失败: %v", err)
	}
	_ = cli.Close()
	if len(statuses) != 1 || statuses[0] != hostkey.StatusUnknown {
		t.Fatalf("应在首次连接询问一次且状态为 unknown，实际 %v", statuses)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("确认后应写入信任存储: %v", err)
	}

	// 第二次连接：密钥已受信任，不应再询问
	cli2 := New(cfg)
	cli2.PromptHostKey = func(string, ssh.PublicKey, hostkey.Status) (bool, error) {
		t.Fatal("已受信任的主机不应再次询问")
		return false, nil
	}
	if err := cli2.Connect(); err != nil {
		t.Fatalf("已信任主机连接失败: %v", err)
	}
	_ = cli2.Close()
}

// TestHostKeyUntrustedNoPrompt 验证不可交互时未受信任的主机直接失败。
func TestHostKeyUntrustedNoPrompt(t *testing.T) {
	srv := sshtest.Start(t)
	cfg := cfgFor(t, srv.Addr, "test")
	cfg.SSH.HostKey = filepath.Join(t.TempDir(), "known_hosts")

	cli := New(cfg) // PromptHostKey 为空
	if err := cli.Connect(); err == nil {
		_ = cli.Close()
		t.Fatal("未受信任且不可交互时应连接失败")
	}
}

// TestHostKeyPromptRejected 验证用户拒绝信任时不写入且连接失败。
func TestHostKeyPromptRejected(t *testing.T) {
	srv := sshtest.Start(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	cfg := cfgFor(t, srv.Addr, "test")
	cfg.SSH.HostKey = path

	cli := New(cfg)
	cli.PromptHostKey = func(string, ssh.PublicKey, hostkey.Status) (bool, error) {
		return false, nil
	}
	if err := cli.Connect(); err == nil {
		_ = cli.Close()
		t.Fatal("拒绝信任后不应建立连接")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("拒绝信任后不应写入信任存储: %v", err)
	}
}
