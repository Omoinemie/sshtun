package socks5

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/sshclient"
	"github.com/Omoinemie/sshtun/internal/sshtest"
)

// testConfig 构造指向测试 SSH 服务器的配置。
func testConfig(t *testing.T, sshAddr string) *config.Config {
	t.Helper()
	host, portStr, err := net.SplitHostPort(sshAddr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return &config.Config{
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
}

// 模拟客户端发起 SOCKS5 CONNECT。
func socks5Connect(t *testing.T, addr, targetHost string, targetPort uint16, hostType byte) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("连接 SOCKS5 失败: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// 方法协商
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		t.Fatalf("方法协商失败: %v", resp)
	}

	// CONNECT 请求
	req := []byte{5, 1, 0, hostType}
	if hostType == 3 {
		req = append(req, byte(len(targetHost)))
		req = append(req, targetHost...)
	} else {
		req = append(req, net.ParseIP(targetHost).To4()...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], targetPort)
	req = append(req, portBytes[:]...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("CONNECT 失败, reply code=%d", reply[1])
	}
	return conn
}

func TestSocks5ThroughSSHTunnel(t *testing.T) {
	// 上游 HTTP 服务
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello-tunnel")
	}))
	defer ts.Close()
	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// 测试 SSH 服务器
	srv := sshtest.Start(t)

	// SSH 客户端
	cfg := testConfig(t, srv.Addr)
	cli := sshclient.New(cfg)
	if err := cli.Connect(); err != nil {
		t.Fatalf("SSH 连接失败: %v", err)
	}
	defer cli.Close()

	// SOCKS5 服务端
	s := &Server{Dial: cli.Dial}
	errCh := make(chan error, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { errCh <- s.Serve(ln) }()

	// 通过 SOCKS5 发起 HTTP 请求（域名形式目标）
	conn := socks5Connect(t, ln.Addr().String(), host, port, 3)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ts.Listener.Addr())
	data, err := io.ReadAll(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	if string(data[len(data)-12:]) != "hello-tunnel" {
		t.Fatalf("响应内容错误: %q", string(data))
	}
	_ = s.Close()
}

func TestSocks5UDPAssociateRejected(t *testing.T) {
	srv := sshtest.Start(t)
	cfg := testConfig(t, srv.Addr)
	cli := sshclient.New(cfg)
	if err := cli.Connect(); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	s := &Server{Dial: cli.Dial}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], 53)
	req := append([]byte{5, 3, 0, 1, 8, 8, 8, 8}, portBytes[:]...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 7 { // command not supported
		t.Fatalf("UDP ASSOCIATE 应返回 7, got %d", reply[1])
	}
}
