package cmd

// 进程内流量统计：按隧道累计其 SSH 通道实际搬运的字节（TUN 流量经 SOCKS5、
// 端口转发经各自的转发管道），由后台采样器按秒差分估算实时速率，供 Web 界面展示。
//
// 口径为应用层计数，只统计经隧道传输的载荷字节：
//   - 上行（up）：本机发往隧道远端（SOCKS5/本地转发上传、远程转发回传）；
//   - 下行（down）：隧道远端发往本机。
//
// 相比读取 TUN 网卡的内核计数，该口径天然覆盖端口转发（forward 模式无 TUN 网卡时
// 也有统计），且不受系统路由回环、网卡计数实现差异等影响。
//
// 跨进程展示：运行实例周期性把计数写入 state.json，Web 进程据此补全未在本进程
// 运行的隧道（本进程运行的隧道始终以自身计数器为准）。

import (
	"sync"
	"time"

	tc "github.com/Omoinemie/sshtun/internal/traffic"
)

// trafficSample 是某条隧道的统计快照（累计字节与字节/秒速率）。
type trafficSample struct {
	Up        int64   `json:"up"`
	Down      int64   `json:"down"`
	UpSpeed   float64 `json:"upSpeed"`
	DownSpeed float64 `json:"downSpeed"`
}

// tunnelTraffic 保存单条隧道统计的最近观测值与速率。
type tunnelTraffic struct {
	// ctr 为本进程运行的隧道计数器；跨进程隧道为 nil，累计值由 state.json 同步。
	ctr *tc.Counter
	// up/down 为最近一次观测到的累计字节，用于差分求速率。
	up, down           int64
	lastUp, lastDown   int64 // 上一次采样时的累计值
	upSpeed, downSpeed float64
	at                 time.Time
	sampled            bool // 是否已建立速率基线
}

// trafficRegistry 维护 tunnel name -> 统计条目，并驱动后台采样器。
type trafficRegistry struct {
	mu   sync.Mutex
	m    map[string]*tunnelTraffic
	once sync.Once
}

var traffic = &trafficRegistry{m: make(map[string]*tunnelTraffic)}

// start 启动后台采样器（幂等）。
func (r *trafficRegistry) start() {
	r.once.Do(func() {
		go func() {
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			for range tick.C {
				r.sampleOnce(time.Now())
			}
		}()
	})
}

// register 登记一条本进程运行的隧道及其计数器并启动采样器；
// 重复登记会重置该隧道的统计（计数器随会话重建，从零开始）。
func (r *trafficRegistry) register(name string, ctr *tc.Counter) {
	r.mu.Lock()
	r.m[name] = &tunnelTraffic{ctr: ctr}
	r.mu.Unlock()
	r.start()
}

// sync 用 state.json 中的统计对齐跨进程隧道的集合：新增缺失项、移除已结束项。
// 跨进程隧道的累计值与速率均由运行实例采集（速率随 state.json 一并落盘），
// Web 端直通显示，不做二次差分（Web 侧 1s 采样对 2s 落盘会产生 0/2 倍跳变）。
// 本进程运行的隧道（ctr 非 nil）以自身计数器为准，不受同步影响。
// remote 为 nil 或空表示运行实例已退出，此时清空跨进程条目。
func (r *trafficRegistry) sync(remote map[string]trafficSample) {
	r.mu.Lock()
	for name, t := range r.m {
		if t.ctr != nil {
			continue
		}
		if _, ok := remote[name]; !ok {
			delete(r.m, name)
		}
	}
	for name, s := range remote {
		if t, ok := r.m[name]; ok {
			if t.ctr != nil {
				continue
			}
			t.up, t.down = s.Up, s.Down
			t.upSpeed, t.downSpeed = s.UpSpeed, s.DownSpeed
			continue
		}
		r.m[name] = &tunnelTraffic{
			up: s.Up, down: s.Down,
			upSpeed: s.UpSpeed, downSpeed: s.DownSpeed,
		}
	}
	r.mu.Unlock()
	if len(r.m) > 0 {
		r.start()
	}
}

// unregister 移除一条隧道（停止/删除时调用），避免残留统计。
func (r *trafficRegistry) unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, name)
}

// sampleOnce 采样一次：读取本进程隧道的累计字节，按时间差估算速率。
// 跨进程隧道（ctr 为 nil）的速率由运行实例提供，这里跳过，避免二次差分。
// 隧道重启（计数器归零）时重建速率基线，避免出现负速率。
func (r *trafficRegistry) sampleOnce(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.m) == 0 {
		return
	}
	for _, t := range r.m {
		if t.ctr == nil {
			continue
		}
		t.up, t.down = t.ctr.Up(), t.ctr.Down()
		if !t.sampled {
			t.lastUp, t.lastDown, t.at, t.sampled = t.up, t.down, now, true
			continue
		}
		dt := now.Sub(t.at).Seconds()
		if dt > 0 {
			if du := t.up - t.lastUp; du >= 0 {
				t.upSpeed = float64(du) / dt
			}
			if dd := t.down - t.lastDown; dd >= 0 {
				t.downSpeed = float64(dd) / dt
			}
		}
		t.lastUp, t.lastDown, t.at = t.up, t.down, now
	}
}

// speed 返回一条本进程隧道的实时速率（供运行实例落盘到 state.json）。
func (r *trafficRegistry) speed(name string) (up, down float64, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.m[name]
	if !ok || t.ctr == nil {
		return 0, 0, false
	}
	return t.upSpeed, t.downSpeed, true
}

// snapshot 返回当前所有隧道的统计拷贝（按隧道名）。
// 本进程运行的隧道直接读计数器，累计值不依赖采样节拍（速率仍由采样器差分得出）。
func (r *trafficRegistry) snapshot() map[string]trafficSample {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]trafficSample, len(r.m))
	for name, t := range r.m {
		if t.ctr != nil {
			t.up, t.down = t.ctr.Up(), t.ctr.Down()
		}
		out[name] = trafficSample{
			Up:        t.up,
			Down:      t.down,
			UpSpeed:   t.upSpeed,
			DownSpeed: t.downSpeed,
		}
	}
	return out
}
