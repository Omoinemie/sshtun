package forwarder

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/sshclient"
	"github.com/Omoinemie/sshtun/internal/sshtest"
)

// 纯回显目标：隔离远端转发反方向数据流。
func TestRemoteForwardEcho(t *testing.T) {
	// 本地回显目标
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // 回显
			}(c)
		}
	}()

	srv := sshtest.Start(t)
	cfg, _, _ := testConfig(t, srv.Addr)
	cfg.Forwards.Remote = []config.ForwardRule{{
		BindAddr: "127.0.0.1", BindPort: 0,
		Target: echoLn.Addr().String(), Raw: "echo",
	}}

	cli := sshclient.New(cfg)
	if err := cli.Connect(); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	mgr := NewManager(cfg, cli.Dial, cli.ListenRemote, func(msg string, args ...any) {
		t.Logf("forwarder: %s %v", msg, args)
	})
	defer mgr.Close()
	if err := mgr.StartRemote(); err != nil {
		t.Fatalf("StartRemote 失败: %v", err)
	}

	serverSide := srv.TriggerForwardedConn(t)
	defer serverSide.Close()

	done := make(chan error, 1)
	go func() {
		if _, err := fmt.Fprint(serverSide, "PING123"); err != nil {
			done <- err
			return
		}
		buf := make([]byte, 7)
		if _, err := io.ReadFull(serverSide, buf); err != nil {
			done <- err
			return
		}
		if string(buf) != "PING123" {
			done <- fmt.Errorf("回显错误: %q", string(buf))
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("回显测试失败: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("回显超时")
	}
}
