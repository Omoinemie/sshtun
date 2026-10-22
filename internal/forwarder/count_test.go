package forwarder

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/Omoinemie/sshtun/internal/config"
)

// pipe 的方向回调按调用方映射计数：aToB 统计 a→b 的字节，bToA 统计反向。
func TestPipeCountsBytes(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()

	var ab, ba int64
	done := make(chan error, 1)
	go func() {
		done <- pipe(a1, b1, func(n int64) { ab += n }, func(n int64) { ba += n })
	}()

	if _, err := a2.Write([]byte("ping")); err != nil {
		t.Fatalf("写入 a 侧失败: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(b2, got); err != nil {
		t.Fatalf("读取 b 侧失败: %v", err)
	}
	if _, err := b2.Write([]byte("pong12")); err != nil {
		t.Fatalf("写入 b 侧失败: %v", err)
	}
	echo := make([]byte, 6)
	if _, err := io.ReadFull(a2, echo); err != nil {
		t.Fatalf("读取 a 侧失败: %v", err)
	}
	_ = a2.Close()
	if err := <-done; err != nil {
		t.Fatalf("pipe 返回错误: %v", err)
	}

	if ab != 4 || ba != 6 {
		t.Errorf("pipe 计数错误: aToB=%d bToA=%d, want 4/6", ab, ba)
	}
}

// 本地转发应把「客户端→隧道远端」记为上传、反向记为下载。
func TestLocalForwardCountsUpDown(t *testing.T) {
	// 目标服务：回显。
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听目标失败: %v", err)
	}
	defer func() { _ = target.Close() }()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	m := &Manager{}
	var up, down int64
	m.Count = func(u, d int64) { up += u; down += d }
	// 直连目标，模拟 SSH 拨号（handleLocal 经 m.dial 建立上游）。
	m.dial = func(network, addr string) (net.Conn, error) { return net.Dial(network, addr) }

	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听本地转发失败: %v", err)
	}
	defer func() { _ = local.Close() }()
	go func() {
		c, err := local.Accept()
		if err != nil {
			return
		}
		m.handleLocal(c, config.ForwardRule{Target: target.Addr().String(), Raw: "test"})
	}()

	c, err := net.Dial("tcp", local.Addr().String())
	if err != nil {
		t.Fatalf("连接本地转发失败: %v", err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("回显读取失败: %v", err)
	}
	_ = c.Close()
	// 计数在转发管道收尾（连接关闭）后落账，稍等其完成。
	time.Sleep(150 * time.Millisecond)

	if up == 0 {
		t.Error("本地转发上传字节应计入（此前完全不统计端口转发流量）")
	}
	if down == 0 {
		t.Error("本地转发下载字节应计入")
	}
}
