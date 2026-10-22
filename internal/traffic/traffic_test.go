package traffic

import (
	"bytes"
	"testing"
)

func TestCounter(t *testing.T) {
	var c Counter
	c.AddUp(100)
	c.AddDown(250)
	c.AddUp(0)
	c.AddDown(-5) // 非法增量忽略
	if c.Up() != 100 || c.Down() != 250 {
		t.Errorf("Counter = up %d down %d, want 100/250", c.Up(), c.Down())
	}
}

// Writer 必须按每次写入实时累计，而不是等底层拷贝结束才一次性记账，
// 否则长连接传输期间统计一直是 0（历史 bug：等 io.Copy 返回才计数）。
func TestWriterCountsPerWrite(t *testing.T) {
	var got int64
	var buf bytes.Buffer
	w := &Writer{W: &buf, Add: func(n int64) { got += n }}

	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("Write 失败: %v", err)
	}
	if got != 5 {
		t.Errorf("首次写入后应已计数 5，实际 %d（必须边写边计）", got)
	}
	if _, err := w.Write([]byte("world!!")); err != nil {
		t.Fatalf("Write 失败: %v", err)
	}
	if got != 12 {
		t.Errorf("累计应为 12，实际 %d", got)
	}
	if buf.String() != "helloworld!!" {
		t.Errorf("底层写入内容错误: %q", buf.String())
	}
}

// Add 为 nil 时只透传不计数，不能 panic。
func TestWriterNilAdd(t *testing.T) {
	var buf bytes.Buffer
	w := &Writer{W: &buf}
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatalf("Write 失败: %v", err)
	}
	if buf.String() != "abc" {
		t.Errorf("底层写入内容错误: %q", buf.String())
	}
}
