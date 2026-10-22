package forwarder

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/sshclient"
	"github.com/Omoinemie/sshtun/internal/sshtest"
)

func testConfig(t *testing.T, sshAddr string) (*config.Config, int, string) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(sshAddr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	cfg := &config.Config{
		Path: t.TempDir() + "/setting.conf",
		SSH: config.SSHConfig{
			Host:           host,
			Port:           port,
			User:           "test",
			Auth:           "password",
			Password:       "test",
			HostKey:        "none",
			Keepalive:      0,
			ConnectTimeout: 5,
		},
	}
	return cfg, port, host
}

func TestLocalForward(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "local-forward-ok")
	}))
	defer ts.Close()
	target := ts.Listener.Addr().String()

	srv := sshtest.Start(t)
	cfg, _, _ := testConfig(t, srv.Addr)
	cfg.Forwards.Local = []config.ForwardRule{{
		BindAddr: "127.0.0.1", BindPort: 0,
		Target: target, Raw: "test",
	}}

	cli := sshclient.New(cfg)
	if err := cli.Connect(); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	mgr := NewManager(cfg, cli.Dial, cli.ListenRemote, nil)
	defer mgr.Close()

	// BindPort 0 时需要实际端口：先试听拿端口再交给 StartLocal
	cfg.Forwards.Local[0].BindPort = 0
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	localAddr := ln.Addr().String()
	_ = ln.Close()
	_, portStr, _ := net.SplitHostPort(localAddr)
	fmt.Sscanf(portStr, "%d", &cfg.Forwards.Local[0].BindPort)

	if err := mgr.StartLocal(); err != nil {
		t.Fatalf("StartLocal 失败: %v", err)
	}

	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Get("http://" + localAddr)
	if err != nil {
		t.Fatalf("经隧道请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "local-forward-ok" {
		t.Fatalf("响应错误: %q", string(body))
	}
}

// 远程转发交给 SSH 层的必须是「明确的地址」：空地址的语义依赖服务端如何解释，
// 这里统一写明监听地址（默认回环，与服务端 -R 默认一致）。
func TestStartRemoteUsesExplicitBindAddr(t *testing.T) {
	cfg := &config.Config{}
	cfg.Forwards.Remote = []config.ForwardRule{
		{BindAddr: "127.0.0.1", BindPort: 9090, Target: "127.0.0.1:8080", Raw: "9090:127.0.0.1:8080"},
		{BindAddr: "", BindPort: 9091, Target: "127.0.0.1:8081", Raw: "9091:127.0.0.1:8081"},
		{BindAddr: "0.0.0.0", BindPort: 9092, Target: "127.0.0.1:8082", Raw: "0.0.0.0:9092:127.0.0.1:8082"},
	}

	var got []string
	mgr := NewManager(cfg, nil, func(addr string) (net.Listener, error) {
		got = append(got, addr)
		return net.Listen("tcp", "127.0.0.1:0")
	}, nil)
	defer mgr.Close()

	if err := mgr.StartRemote(); err != nil {
		t.Fatalf("StartRemote 失败: %v", err)
	}
	want := []string{"127.0.0.1:9090", "127.0.0.1:9091", "0.0.0.0:9092"}
	if len(got) != len(want) {
		t.Fatalf("监听地址数量不符: got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 条监听地址应为 %s，实际 %s", i+1, want[i], got[i])
		}
	}
}

func TestRemoteForward(t *testing.T) {
	// 本地目标
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("本地目标收到请求: %s", r.URL.Path)
		fmt.Fprint(w, "remote-forward-ok")
	}))
	defer ts.Close()
	localTarget := ts.Listener.Addr().String()

	srv := sshtest.Start(t)
	cfg, sshPort, sshHost := testConfig(t, srv.Addr)
	cfg.Forwards.Remote = []config.ForwardRule{{
		BindAddr: "127.0.0.1", BindPort: 0,
		Target: localTarget, Raw: "test",
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

	// 服务端侧主动投递一条 forwarded-tcpip 连接，模拟外部用户连接远端监听端口
	serverSide := srv.TriggerForwardedConn(t)
	defer serverSide.Close()

	// 发送 HTTP 请求，应经隧道到达本地 httptest 目标
	if n, err := fmt.Fprintf(serverSide, "GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", sshHost, sshPort); err != nil {
		t.Fatalf("写入请求失败: %v (n=%d)", err, n)
	}
	type readResult struct {
		data []byte
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(serverSide)
		ch <- readResult{data, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil && r.err != io.EOF {
			t.Fatalf("读取响应失败: %v", r.err)
		}
		if len(r.data) == 0 {
			t.Fatal("响应为空")
		}
		want := "remote-forward-ok"
		if len(r.data) < len(want) || string(r.data[len(r.data)-len(want):]) != want {
			t.Fatalf("响应内容错误: %q", string(r.data))
		}
	case <-time.After(8 * time.Second):
		t.Fatal("读取响应超时")
	}
}

// 单条远程转发被服务端拒绝时，不应阻断其余规则，并应聚合返回错误，
// 供上层（TUN 模式）决定仅告警继续运行。
func TestStartRemoteAggregatesDenials(t *testing.T) {
	cfg := &config.Config{}
	cfg.Forwards.Remote = []config.ForwardRule{
		{BindAddr: "127.0.0.1", BindPort: 9090, Target: "127.0.0.1:8080", Raw: "9090:127.0.0.1:8080"},
		{BindAddr: "127.0.0.1", BindPort: 9091, Target: "127.0.0.1:8081", Raw: "9091:127.0.0.1:8081"},
	}

	var got []string
	mgr := NewManager(cfg, nil, func(addr string) (net.Listener, error) {
		got = append(got, addr)
		if addr == "127.0.0.1:9090" {
			return nil, errors.New("ssh: tcpip-forward request denied by peer")
		}
		return net.Listen("tcp", "127.0.0.1:0")
	}, nil)
	defer mgr.Close()

	err := mgr.StartRemote()
	if err == nil {
		t.Fatal("被拒规则应产生错误")
	}
	if !strings.Contains(err.Error(), "9090") {
		t.Errorf("错误应指明失败的规则: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("被拒规则不应阻断后续规则: got=%v", got)
	}
}
