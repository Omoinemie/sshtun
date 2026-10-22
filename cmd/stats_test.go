package cmd

import (
	"testing"
	"time"

	tc "github.com/Omoinemie/sshtun/internal/traffic"
)

// 采样器按累计计数差分求速率；计数随隧道重启归零时不产生负速率。
func TestTrafficRegistrySampleAndReset(t *testing.T) {
	r := &trafficRegistry{m: make(map[string]*tunnelTraffic)}
	ctr := &tc.Counter{}
	r.register("office", ctr)

	ctr.AddUp(1000)
	ctr.AddDown(2000)
	t0 := time.Now()
	r.sampleOnce(t0) // 建立速率基线

	ctr.AddUp(500)
	ctr.AddDown(1500)
	r.sampleOnce(t0.Add(time.Second))

	s := r.snapshot()["office"]
	if s.Up != 1500 || s.Down != 3500 {
		t.Errorf("累计字节错误: up=%d down=%d, want 1500/3500", s.Up, s.Down)
	}
	if s.UpSpeed != 500 || s.DownSpeed != 1500 {
		t.Errorf("速率错误: up=%.0f down=%.0f, want 500/1500", s.UpSpeed, s.DownSpeed)
	}

	// 模拟重启：计数器重建（归零），重新登记后不出现负速率或跨会话串值。
	ctr2 := &tc.Counter{}
	r.register("office", ctr2)
	r.sampleOnce(t0.Add(2 * time.Second))
	ctr2.AddUp(10)
	r.sampleOnce(t0.Add(3 * time.Second))
	s = r.snapshot()["office"]
	if s.Up != 10 || s.UpSpeed != 10 {
		t.Errorf("重启后统计应从零开始: up=%d speed=%.0f, want 10/10", s.Up, s.UpSpeed)
	}

	r.unregister("office")
	if _, ok := r.snapshot()["office"]; ok {
		t.Error("注销后不应残留统计条目")
	}
}

// 本进程运行的隧道以自身计数器为准；跨进程隧道由 state.json 的累计值同步与清理。
func TestTrafficRegistrySync(t *testing.T) {
	r := &trafficRegistry{m: make(map[string]*tunnelTraffic)}
	local := &tc.Counter{}
	local.AddUp(42)
	r.register("local", local)

	r.sync(map[string]trafficSample{"remote": {Up: 100, Down: 200, UpSpeed: 10, DownSpeed: 20}})
	s := r.snapshot()["remote"]
	if s.Up != 100 || s.Down != 200 {
		t.Errorf("跨进程隧道应取 state.json 累计值: %+v", s)
	}
	// 跨进程速率由运行实例提供并直通显示，Web 端不做二次差分。
	if s.UpSpeed != 10 || s.DownSpeed != 20 {
		t.Errorf("跨进程速率应直通 state.json 的值: %+v", s)
	}
	if _, _, ok := r.speed("remote"); ok {
		t.Error("跨进程隧道不应有本进程采样的速率")
	}
	// 同步不应覆盖本进程计数器。
	r.sync(map[string]trafficSample{
		"remote": {Up: 1, Down: 1, UpSpeed: 1, DownSpeed: 1},
		"local":  {Up: 999, Down: 999, UpSpeed: 999, DownSpeed: 999},
	})
	if got := r.snapshot()["local"]; got.Up != 42 {
		t.Errorf("本进程隧道不应被 state.json 覆盖: up=%d", got.Up)
	}
	// 远端已结束的隧道应被清理。
	r.sync(map[string]trafficSample{})
	if _, ok := r.snapshot()["remote"]; ok {
		t.Error("远端已结束的隧道应从统计中移除")
	}
	if _, ok := r.snapshot()["local"]; !ok {
		t.Error("本进程运行的隧道不应被同步移除")
	}
}
