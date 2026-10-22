package cmd

// Web 会话控制：复用 CLI 的 runSession 与控制通道，让 Web 界面以同样的语义启停隧道；
// 并提供账号密码登录后的内存会话表。

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/daemon"
	"github.com/Omoinemie/sshtun/internal/logging"
	"github.com/Omoinemie/sshtun/internal/store"
)

const (
	// sessionCookieName 是浏览器会话令牌的 Cookie 名（便于刷新后续用）。
	sessionCookieName = "sshtun_session"
	// webSessionTTL 是会话有效期（滑动续期）。
	webSessionTTL = 12 * time.Hour
	// webSessionAbsoluteTTL 是会话的绝对生存上限：无论是否持续使用，超过即失效，
	// 避免被盗令牌被反复使用而永不失效。
	webSessionAbsoluteTTL = 24 * time.Hour
	// webSessionGCInterval 是过期会话的回收周期。
	webSessionGCInterval = 10 * time.Minute
)

// session 是一个已签发的登录会话。
type session struct {
	username  string
	issuedAt  time.Time
	expiresAt time.Time
}

// sessionStore 是内存会话表：登录成功签发随机令牌，访问时校验并滑动续期。
type sessionStore struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]session
}

func newSessionStore(ttl time.Duration) *sessionStore {
	s := &sessionStore{ttl: ttl, m: make(map[string]session)}
	s.startGC()
	return s
}

// startGC 周期性清理过期会话：未被访问的过期项不会自行消失，长期运行需主动回收。
func (s *sessionStore) startGC() {
	go func() {
		t := time.NewTicker(webSessionGCInterval)
		defer t.Stop()
		for range t.C {
			s.gc(time.Now())
		}
	}()
}

func (s *sessionStore) gc(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, sess := range s.m {
		if now.After(sess.expiresAt) || now.After(sess.issuedAt.Add(webSessionAbsoluteTTL)) {
			delete(s.m, tok)
		}
	}
}

// issue 为用户签发新令牌，返回令牌与其有效期秒数。
func (s *sessionStore) issue(username string) (string, int) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", 0
	}
	tok := hex.EncodeToString(b)
	now := time.Now()
	s.mu.Lock()
	s.m[tok] = session{username: username, issuedAt: now, expiresAt: now.Add(s.ttl)}
	s.mu.Unlock()
	return tok, int(s.ttl.Seconds())
}

// valid 校验令牌；有效则滑动续期。
func (s *sessionStore) valid(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[token]
	if !ok {
		return false
	}
	now := time.Now()
	if now.After(sess.expiresAt) || now.After(sess.issuedAt.Add(webSessionAbsoluteTTL)) {
		delete(s.m, token)
		return false
	}
	sess.expiresAt = now.Add(s.ttl)
	s.m[token] = sess
	return true
}

// revoke 使令牌立即失效（退出登录）。
func (s *sessionStore) revoke(token string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	delete(s.m, token)
	s.mu.Unlock()
}

// constantEqual 以常量时间比较两个字符串，避免时序侧信道。
func constantEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

/* ------------------------------ 运行时控制 ------------------------------ */

// webRunningSet 返回当前运行中的隧道名集合与状态；未运行时返回 (nil, nil)。
// 集合以隧道名（当前名）为键：控制通道按名字操作隧道。
func webRunningSet() (map[string]bool, *daemon.State) {
	s, _ := daemon.ActiveState()
	if s == nil {
		return nil, nil
	}
	set := make(map[string]bool, len(s.Tunnels))
	for _, t := range s.Tunnels {
		set[t.Name] = true
	}
	return set, s
}

// webRunningUIDs 返回运行中隧道的 UID 集合（隧道改名后仍能对上号）。
func webRunningUIDs(s *daemon.State) map[string]bool {
	set := map[string]bool{}
	if s == nil {
		return set
	}
	for _, t := range s.Tunnels {
		if t.UID != "" {
			set[t.UID] = true
		}
	}
	return set
}

// webEnabledNames 返回数据库中启用中的隧道名。
func webEnabledNames(st *store.Store) ([]string, error) {
	all, err := st.ListTunnels()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, t := range all {
		if t.Enabled {
			out = append(out, t.Name)
		}
	}
	return out, nil
}

// webStart 启动隧道：names 为空表示全部启用隧道。
// 已有实例在运行时经控制通道在原实例内新增；否则拉起独立的后台实例承载隧道。
//
// 隧道一律运行在独立进程里，Web 进程不接触任何凭据：
// 即使 Web 界面被攻破，其内存里也不会出现解密后的 SSH 密码。
func webStart(cfg *config.Config, names []string) error {
	// 串行化「拉起后台实例」：并发点击启动时只派生一个进程，
	// 后到的请求在锁释放后重新检查运行状态，走「已有实例」分支。
	webStartMu.Lock()
	defer webStartMu.Unlock()

	running, _ := webRunningSet()
	if running != nil {
		st, err := store.Open(cfg.App.DB)
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()
		all, err := st.ListTunnels()
		if err != nil {
			return err
		}
		var toStart []string
		if len(names) == 0 {
			for _, t := range all {
				if t.Enabled && !running[t.Name] {
					toStart = append(toStart, t.Name)
				}
			}
		} else {
			for _, n := range names {
				if !running[n] {
					toStart = append(toStart, n)
				}
			}
		}
		if len(toStart) == 0 {
			return nil
		}
		return sendControl(opStart, toStart)
	}

	// 未运行：先同步校验目标隧道是否可用，再拉起后台实例承载。
	st, err := store.Open(cfg.App.DB)
	if err != nil {
		return err
	}
	tunnels, err := resolveTunnels(st, names)
	_ = st.Close()
	if err != nil {
		return err
	}
	if len(tunnels) == 0 {
		return errNoTunnels
	}
	pid, err := startTunnelDaemon(cfg, names)
	if err != nil {
		return err
	}
	return waitDaemonReady(pid)
}

// webStartMu 串行化 webStart，避免并发请求重复派生后台实例。
var webStartMu sync.Mutex

// webOwnedDaemon 记录本 Web 进程是否派生了后台实例。
// 派生者负责在退出前停掉这些隧道，与原先「隧道跑在本进程内、随进程退出
// 而停止」的语义保持一致；非本进程派生（如 CLI 另起的实例）不受影响。
var webOwnedDaemon atomic.Bool

// startTunnelDaemon 拉起承载隧道的后台进程，返回其 PID。
//
// 子进程复用 start 子命令并带 daemonEnv 标记：startInstance 检测到该标记会
// 跳过再次后台化，直接进入 runSession；该标记同时让子进程进入非交互模式
// （无终端时不做凭据/主机密钥提示，日志只写文件）。
//
// 命令行显式带 --config，确保子进程与本进程使用同一份配置；
// 数据库路径按工作目录解析，而子进程继承本进程的工作目录，两者一致。
func startTunnelDaemon(cfg *config.Config, names []string) (int, error) {
	args := []string{"start", "--config", cfg.Path}
	args = append(args, names...)
	pid, err := daemon.Daemonize(args, map[string]string{daemonEnv: "1"})
	if err != nil {
		return 0, err
	}
	webOwnedDaemon.Store(true)
	return pid, nil
}

// stopOwnedDaemon 停掉本进程派生实例所承载的隧道（非派生者则什么都不做）。
// 供 Web 进程退出前调用；托盘退出走 /api/shutdown 时也会经过这里，两条路径幂等。
func stopOwnedDaemon() {
	if !webOwnedDaemon.Load() {
		return
	}
	webOwnedDaemon.Store(false)
	if err := webStop(nil); err != nil {
		logging.Warn("failed to stop the tunnels", "err", err)
	}
}

// waitDaemonReady 等待后台实例就绪：state.json 落盘且 PID 与之一致。
//
// 子进程提前退出说明启动失败（如所有隧道均启动失败）；各条隧道的具体原因
// 已由实例登记到失败表（跨进程共享），这里汇总进错误信息一并回传。
func waitDaemonReady(pid int) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if s, _ := daemon.ActiveState(); s != nil && s.Pid == pid {
			return nil
		}
		if !daemon.IsAlive(pid) {
			return fmt.Errorf("the background instance exited, the start failed%s", failureDetail())
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for the background instance to become ready%s", failureDetail())
}

// failureDetail 汇总失败登记表中的原因，供启动失败时给出可读提示。
func failureDetail() string {
	m := loadFailures()
	if len(m) == 0 {
		return " (see the failure records or the log for details)"
	}
	parts := make([]string, 0, len(m))
	for name, f := range m {
		parts = append(parts, fmt.Sprintf("%s: %s", name, f.Message))
	}
	sort.Strings(parts)
	return ": " + strings.Join(parts, "; ")
}

// webStop 停止隧道：names 为空表示停止全部运行中的隧道。
func webStop(names []string) error {
	running, s := webRunningSet()
	if running == nil {
		return nil
	}
	var toStop []string
	if len(names) == 0 {
		for _, t := range s.Tunnels {
			toStop = append(toStop, t.Name)
		}
	} else {
		for _, n := range names {
			if running[n] {
				toStop = append(toStop, n)
			}
		}
	}
	if len(toStop) == 0 {
		return nil
	}
	return sendControl(opStop, toStop)
}

// webRestart 重启隧道：names 为空表示全部启用隧道；未运行时等价于 webStart。
func webRestart(cfg *config.Config, names []string) error {
	running, _ := webRunningSet()
	if running == nil {
		return webStart(cfg, names)
	}
	if len(names) > 0 {
		return sendControl(opRestart, names)
	}
	st, err := store.Open(cfg.App.DB)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	enabled, err := webEnabledNames(st)
	if err != nil {
		return err
	}
	if len(enabled) == 0 {
		return nil
	}
	return sendControl(opRestart, enabled)
}

// runPendingAction 在提权重启后自动续跑此前被权限拦截的动作。
func runPendingAction(cfg *config.Config, action string, names []string) {
	var err error
	switch action {
	case "start":
		if err = webStart(cfg, names); err == nil {
			logging.Info("the tunnels have been started automatically after elevating", "names", names)
		}
	case "restart":
		if err = webRestart(cfg, names); err == nil {
			logging.Info("the tunnels have been restarted automatically after elevating", "names", names)
		}
	}
	if err != nil {
		logging.Error("the automatic action after elevating failed", "action", action, "err", err)
	}
}
