// Package traffic 提供隧道级的应用层流量计数：按 SSH 通道实际搬运的字节累计，
// 覆盖 TUN（经 SOCKS5 转发）、本地转发与远程转发，与网卡/系统层实现解耦。
package traffic

import (
	"io"
	"sync/atomic"
)

// Counter 累计一条隧道经 SSH 收发的字节，可被多条连接并发增减。
type Counter struct {
	up   atomic.Int64
	down atomic.Int64
}

// AddUp 累加上传字节（本机 → 隧道远端）；n <= 0 时忽略。
func (c *Counter) AddUp(n int64) {
	if n > 0 {
		c.up.Add(n)
	}
}

// AddDown 累加下载字节（隧道远端 → 本机）；n <= 0 时忽略。
func (c *Counter) AddDown(n int64) {
	if n > 0 {
		c.down.Add(n)
	}
}

// Up 返回累计上传字节。
func (c *Counter) Up() int64 { return c.up.Load() }

// Down 返回累计下载字节。
func (c *Counter) Down() int64 { return c.down.Load() }

// Writer 包装底层写入器，把每次成功写入的字节数实时交给 add 回调，
// 实现「边拷贝边计数」。流量统计必须逐块累计：若等 io.Copy 结束再记账，
// 长连接（大文件下载、流媒体）在传输期间累计值与速率会一直是 0。
type Writer struct {
	W   io.Writer
	Add func(n int64)
}

// Write 写入并按实际写入字节数计数。
func (w *Writer) Write(p []byte) (int, error) {
	n, err := w.W.Write(p)
	if n > 0 && w.Add != nil {
		w.Add(int64(n))
	}
	return n, err
}
