package socks5

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// pipe 应按方向累计字节：a→b 记为上传，b→a 记为下载。
func TestPipeCountsBytes(t *testing.T) {
	c1, c2 := net.Pipe() // c1 作为本地客户端连接传入 pipe
	u1, u2 := net.Pipe() // u1 作为上游连接传入 pipe

	var up, down int64
	done := make(chan struct{})
	go func() {
		pipe(c1, u1, func(u, d int64) { up += u; down += d })
		close(done)
	}()

	if _, err := c2.Write([]byte("hello")); err != nil {
		t.Fatalf("写入客户端侧失败: %v", err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(u2, got); err != nil {
		t.Fatalf("读取上游侧失败: %v", err)
	}
	if _, err := u2.Write([]byte("world!")); err != nil {
		t.Fatalf("写入上游侧失败: %v", err)
	}
	got2 := make([]byte, 6)
	if _, err := io.ReadFull(c2, got2); err != nil {
		t.Fatalf("读取客户端侧失败: %v", err)
	}
	_ = c2.Close()
	<-done

	if up != 5 || down != 6 {
		t.Errorf("pipe 计数错误: up=%d down=%d, want 5/6", up, down)
	}
}

// 传输未结束（连接仍打开）时计数必须已经增长：
// 历史 bug 是等 io.Copy 结束才累加，导致长连接下载期间统计恒为 0。
func TestPipeCountsDuringTransfer(t *testing.T) {
	c1, c2 := net.Pipe()
	u1, u2 := net.Pipe()

	var down atomic.Int64
	done := make(chan struct{})
	go func() {
		pipe(c1, u1, func(u, d int64) {
			if d > 0 {
				down.Add(d)
			}
		})
		close(done)
	}()

	// 上游持续发送 1MB，客户端侧持续排空，连接保持打开。
	go func() { _, _ = u2.Write(make([]byte, 1024*1024)) }()
	go func() { _, _ = io.Copy(io.Discard, c2) }()

	// 只要连接还开着（done 未关闭）且计数已增长，就说明是边传边计。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && down.Load() == 0 {
		select {
		case <-done:
			t.Fatal("pipe 已结束，无法验证传输中途的计数")
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if down.Load() == 0 {
		t.Error("连接仍打开时计数应已增长，实际为 0（计数被推迟到拷贝结束）")
	}

	_ = c2.Close()
	_ = u2.Close()
	<-done
}
