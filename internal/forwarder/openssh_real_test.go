package forwarder

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/sshclient"
)

// 对照真实 OpenSSH 的对照实验（默认跳过，需要外部 sshd）：
//
//	# 服务端：/usr/sbin/sshd -f /tmp/sshdtest/sshd_config -E /tmp/sshdtest/sshd.log
//	SSHD_ADDR=127.0.0.1:2222 SSHD_USER=xxx SSHD_PASS=xxx \
//	  go test ./internal/forwarder -run TestRealOpenSSH -v
func realSSHClient(t *testing.T) *sshclient.Client {
	t.Helper()
	addr := os.Getenv("SSHD_ADDR")
	if addr == "" {
		t.Skip("未设置 SSHD_ADDR（需外部 OpenSSH 服务端）")
	}
	cfg, _, _ := testConfig(t, addr)
	cfg.SSH.User = os.Getenv("SSHD_USER")
	cfg.SSH.Password = os.Getenv("SSHD_PASS")
	cli := sshclient.New(cfg)
	if err := cli.Connect(); err != nil {
		t.Fatal(err)
	}
	return cli
}

// 回显服务：远程转发最终要连到的“本地目标”。
func startEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln
}

// 请求不同形式的监听地址，都应能经真实 OpenSSH 建立转发并打通数据。
func TestRealOpenSSHRemoteForward(t *testing.T) {
	cli := realSSHClient(t)
	defer cli.Close()
	target := startEcho(t)

	for _, bindAddr := range []string{"127.0.0.1", ""} {
		t.Run("bind="+bindAddr, func(t *testing.T) {
			listenArg := net.JoinHostPort(bindAddr, "0")
			ln, err := cli.ListenRemote(listenArg)
			if err != nil {
				t.Fatalf("ListenRemote(%q) 失败: %v", listenArg, err)
			}
			defer ln.Close()
			remotePort := ln.Addr().(*net.TCPAddr).Port
			t.Logf("远端监听端口: %d（请求 %q）", remotePort, listenArg)

			// 客户端侧接受并转发到回显服务（等价于 Manager.serveRemote）
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				up, err := net.Dial("tcp", target.Addr().String())
				if err != nil {
					t.Errorf("连接本地目标失败: %v", err)
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
				_, _ = io.Copy(c, up)
			}()

			// 模拟「服务端一侧的外部用户」发起连接
			time.Sleep(300 * time.Millisecond)
			c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)))
			if err != nil {
				t.Fatalf("连接远端监听端口失败: %v", err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			msg := "hello-through-openssh"
			if _, err := fmt.Fprintf(c, "%s", msg); err != nil {
				t.Fatalf("写入失败: %v", err)
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Fatalf("回读失败（转发未打通）: %v", err)
			}
			if string(buf) != msg {
				t.Fatalf("回显内容不符: %q", string(buf))
			}
		})
	}
}

// 服务端端口被占用时，OpenSSH 会拒绝 tcpip-forward；错误信息应给出可操作的排查线索。
func TestRealOpenSSHPortInUseHint(t *testing.T) {
	cli := realSSHClient(t)
	defer cli.Close()

	// 占用一个端口（sshd 与被测程序同机，故为本机占用）
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.Addr().(*net.TCPAddr).Port

	cfg := &config.Config{}
	cfg.Forwards.Remote = []config.ForwardRule{{
		BindAddr: "127.0.0.1", BindPort: port,
		Target: "127.0.0.1:9", Raw: fmt.Sprintf("%d:127.0.0.1:9", port),
	}}
	mgr := NewManager(cfg, nil, cli.ListenRemote, nil)
	defer mgr.Close()

	err = mgr.StartRemote()
	if err == nil {
		t.Fatal("端口被占用时服务端应拒绝远程转发")
	}
	if !strings.Contains(err.Error(), "denied by peer") || !strings.Contains(err.Error(), "AllowTcpForwarding") {
		t.Fatalf("错误信息应包含拒绝原因与排查线索，实际: %v", err)
	}
}
