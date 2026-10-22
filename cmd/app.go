// Package cmd 会话运行器：从数据库读取启用中的隧道并逐条启动，
// 并在运行期通过控制通道按名启停/重启单条隧道。
package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/daemon"
	"github.com/Omoinemie/sshtun/internal/logging"
	"github.com/Omoinemie/sshtun/internal/store"
	"github.com/Omoinemie/sshtun/internal/tun2socks"
)

// 会话模式。
const (
	ModeTun     = "tun"
	ModeForward = "forward"
)

// exitEvent 是一条隧道 tun2socks 的退出事件。
// sess 标识事件来源会话：重启后新会话与旧会话同名，
// run() 据此忽略旧会话的残留退出事件，避免误杀刚重启的隧道。
type exitEvent struct {
	name string
	sess *tunnelSession
	err  error
}

// runtimeManager 在单进程内管理一组隧道会话，支持运行期按名启停/重启。
type runtimeManager struct {
	base      *config.Config
	mode      string
	st        *store.Store
	startedAt time.Time

	sessions map[string]*tunnelSession
	order    []string

	// locks 保存各隧道占用锁（同一隧道全局只允许一个实例持有）。
	locks map[string]*daemon.TunnelLock

	exitCh chan exitEvent
}

// runSession 依据 names 挑选隧道并逐条启动，随后进入事件循环：等待退出信号、
// 隧道异常退出或来自 CLI 的按名控制请求，直到没有隧道在运行为止。
//
// names 为空或含 "all" 表示全部启用隧道；否则为逗号/参数分隔的隧道名列表，
// 不存在或已停用的名字仅告警跳过。单条隧道启动失败同样仅告警跳过（失败隔离），
// 不阻断其余隧道；若没有任何隧道成功启动则返回错误。
func runSession(base *config.Config, mode string, names []string) error {
	if err := logging.Setup(base.Log.Level, base.Log.Dir, logConsole(base)); err != nil {
		return fmt.Errorf("failed to initialize the logger: %w", err)
	}
	if mode == ModeTun && !hasPrivileges() {
		return errNeedPrivilege
	}

	st, err := store.Open(base.App.DB)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	tunnels, err := resolveTunnels(st, names)
	if err != nil {
		return err
	}
	if len(tunnels) == 0 {
		return errNoTunnels
	}

	m := &runtimeManager{
		base:      base,
		mode:      mode,
		st:        st,
		startedAt: time.Now(),
		sessions:  make(map[string]*tunnelSession),
		locks:     make(map[string]*daemon.TunnelLock),
		exitCh:    make(chan exitEvent, 32),
	}
	cleanControlFiles()

	// 串行启动：前台交互式凭据提示不会交错，且失败可即时反馈。
	for _, t := range tunnels {
		if err := m.add(t.Name); err != nil {
			if errors.Is(err, daemon.ErrTunnelInUse) {
				// 已被其它实例（后台守护/GUI 后端）占用：不是故障，不登记失败信息。
				logging.Warn("tunnel already in use by another instance, skipping", "tunnel", t.Name, "err", err)
				fmt.Printf("Tunnel %s failed to start: %v\n", t.Name, err)
				continue
			}
			recordFailure(t.Name, err)
			logging.Warn("tunnel failed to start, skipping it", "tunnel", t.Name, "err", err)
			fmt.Printf("Tunnel %s failed to start: %v\n", t.Name, err)
			continue
		}
		clearFailure(t.Name)
	}
	if len(m.sessions) == 0 {
		return errors.New("all tunnels failed to start, exiting")
	}

	if err := m.saveState(); err != nil {
		logging.Warn("failed to save the running state", "err", err)
	}

	running := m.list()
	logging.Info("sshtun running", "mode", mode, "pid", os.Getpid(), "tunnels", strings.Join(running, ","))
	fmt.Printf("sshtun started: %s, %d tunnel(s) (%s), press Ctrl+C to exit\n",
		modeDescription(mode), len(running), strings.Join(running, ", "))

	return m.run()
}

// logConsole 决定日志是否同时输出到控制台。
//   - [log] console = true/false 显式指定；
//   - 未指定或为 auto 时：前台运行（可交互）输出到控制台，便于实时观察；
//     后台守护子进程没有控制台，仅写日志文件。
func logConsole(cfg *config.Config) bool {
	switch strings.ToLower(strings.TrimSpace(cfg.Log.Console)) {
	case "on", "true", "yes", "1":
		return true
	case "off", "false", "no", "0":
		return false
	}
	return isInteractive()
}

// add 从数据库载入并启动一条隧道会话；已运行或不满足唯一性约束时报错。
func (m *runtimeManager) add(name string) error {
	if _, ok := m.sessions[name]; ok {
		return fmt.Errorf("tunnel %s is already running", name)
	}
	// 先占用隧道锁：同一条隧道全局只允许一个实例（前台 CLI / 后台守护 / GUI 后端
	// 共用同一把锁），避免多个实例创建同名 TUN 适配器而互相拆台。
	lock, err := daemon.AcquireTunnelLock(name)
	if err != nil {
		return err
	}
	release := func() { lock.Release() }
	t, err := m.st.GetTunnel(name)
	if err != nil {
		release()
		return err
	}
	if !t.Enabled {
		release()
		return fmt.Errorf("tunnel %s is disabled", name)
	}
	if err := m.checkUnique(t); err != nil {
		release()
		return err
	}
	rt := t.RuntimeConfig(m.base)
	s, err := startTunnel(name, t.UID, rt, m.mode, dbSaver{st: m.st, name: name})
	if err != nil {
		release()
		return err
	}
	m.sessions[name] = s
	m.locks[name] = lock
	m.order = append(m.order, name)
	if ch := s.waitErr(); ch != nil {
		go func(nm string, sess *tunnelSession, c <-chan error) {
			m.exitCh <- exitEvent{name: nm, sess: sess, err: <-c}
		}(name, s, ch)
	}
	return nil
}

// remove 停止并移除一条隧道会话。
func (m *runtimeManager) remove(name string) {
	s, ok := m.sessions[name]
	if !ok {
		return
	}
	s.Stop()
	delete(m.sessions, name)
	if lock, ok := m.locks[name]; ok {
		lock.Release()
		delete(m.locks, name)
	}
	for i, n := range m.order {
		if n == name {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
}

// isRunning 报告隧道是否在运行中。
func (m *runtimeManager) isRunning(name string) bool {
	_, ok := m.sessions[name]
	return ok
}

// list 返回当前运行中的隧道名（按启动顺序）。
func (m *runtimeManager) list() []string {
	out := make([]string, 0, len(m.order))
	for _, n := range m.order {
		if _, ok := m.sessions[n]; ok {
			out = append(out, n)
		}
	}
	return out
}

// checkUnique 校验新隧道与运行中隧道的 TUN 名称/地址不冲突。
func (m *runtimeManager) checkUnique(t *store.Tunnel) error {
	for _, n := range m.order {
		s := m.sessions[n]
		if s == nil || s.cfg == nil {
			continue
		}
		if s.cfg.Tun.Name == t.TunName {
			return fmt.Errorf("tun_name conflicts with tunnel %q: %s", n, t.TunName)
		}
		if s.cfg.Tun.Address == t.TunAddress {
			return fmt.Errorf("tun_address conflicts with tunnel %q: %s", n, t.TunAddress)
		}
	}
	return nil
}

// stopAll 停止全部会话。
func (m *runtimeManager) stopAll() {
	for _, n := range m.order {
		if s := m.sessions[n]; s != nil {
			s.Stop()
		}
	}
	for _, l := range m.locks {
		l.Release()
	}
	m.sessions = make(map[string]*tunnelSession)
	m.locks = make(map[string]*daemon.TunnelLock)
	m.order = nil
}

// saveState 汇总各隧道的运行状态，供 `status`/`stop` 使用。
func (m *runtimeManager) saveState() error {
	sts := make([]daemon.TunnelState, 0, len(m.sessions))
	for _, n := range m.order {
		if s := m.sessions[n]; s != nil {
			sts = append(sts, s.stateInfo())
		}
	}
	return daemon.SaveState(&daemon.State{
		Pid:        os.Getpid(),
		Mode:       m.mode,
		DBPath:     m.base.App.DB,
		ConfigPath: m.base.Path,
		StartedAt:  m.startedAt,
		Tunnels:    sts,
	})
}

// run 是主事件循环：处理退出信号、隧道异常退出与按名控制请求。
func (m *runtimeManager) run() error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	cmdCh := make(chan controlRequest, 8)
	stopPoller := func() {}
	if reqPath, err := controlReqPath(); err == nil {
		stopPoller = startControlPoller(reqPath, cmdCh)
	}
	defer stopPoller()

	// 周期性把流量计数写入 state.json，供其它进程（如 Web 界面）展示统计。
	persist := time.NewTicker(2 * time.Second)
	defer persist.Stop()

	for {
		if len(m.sessions) == 0 {
			logging.Info("no tunnels left running, exiting")
			// 保留响应文件供发起 stop 的 CLI 读取；请求文件已在轮询中消费。
			_ = daemon.ClearState()
			return nil
		}
		select {
		case sig := <-sigCh:
			logging.Info("received exit signal", "signal", sig.String())
			m.stopAll()
			_ = daemon.ClearState()
			logging.Info("resources cleaned up")
			return nil
		case <-persist.C:
			if err := m.saveState(); err != nil {
				logging.Debug("failed to refresh the running state", "err", err)
			}
		case ev := <-m.exitCh:
			if !m.isCurrent(ev) {
				continue // 主动停止/重启导致的旧会话退出，忽略
			}
			logging.Error("tun2socks exited unexpectedly", "tunnel", ev.name, "err", ev.err)
			fmt.Printf("tun2socks of tunnel %s exited unexpectedly, the tunnel has been stopped\n", ev.name)
			m.remove(ev.name)
			_ = m.saveState()
		case req := <-cmdCh:
			m.handleControl(req)
		}
	}
}

// isCurrent 报告退出事件是否来自当前仍在运行的会话。
// 重启后新旧会话同名，旧会话的残留退出事件必须忽略，否则会误杀刚重启的隧道；
// 已被主动停止的隧道同样不处理其残留事件。
func (m *runtimeManager) isCurrent(ev exitEvent) bool {
	cur, ok := m.sessions[ev.name]
	return ok && cur == ev.sess
}

// handleControl 在进程内按名执行 start/stop/restart，并把结果写回 CLI。
func (m *runtimeManager) handleControl(req controlRequest) {
	var lines []string
	switch req.Op {
	case opStart:
		for _, name := range req.Names {
			if m.isRunning(name) {
				lines = append(lines, fmt.Sprintf("tunnel %s is already running, skipping", name))
				continue
			}
			if err := m.add(name); err != nil {
				recordFailure(name, err)
				lines = append(lines, fmt.Sprintf("tunnel %s failed to start: %v", name, err))
			} else {
				clearFailure(name)
				lines = append(lines, fmt.Sprintf("started tunnel %s", name))
			}
		}
	case opStop:
		for _, name := range req.Names {
			if !m.isRunning(name) {
				lines = append(lines, fmt.Sprintf("tunnel %s is not running, skipping", name))
				continue
			}
			m.remove(name)
			lines = append(lines, fmt.Sprintf("stopped tunnel %s", name))
		}
	case opRestart:
		for _, name := range req.Names {
			if m.isRunning(name) {
				m.remove(name)
			}
			if err := m.add(name); err != nil {
				recordFailure(name, err)
				lines = append(lines, fmt.Sprintf("tunnel %s failed to start: %v", name, err))
			} else {
				clearFailure(name)
				lines = append(lines, fmt.Sprintf("restarted tunnel %s", name))
			}
		}
	default:
		writeControlResponse(req.ID, controlResponse{OK: false, Error: fmt.Sprintf("unknown operation: %s", req.Op)})
		return
	}
	_ = m.saveState()
	writeControlResponse(req.ID, controlResponse{OK: true, Lines: lines})
}

// resolveTunnels 按可选的隧道名挑选要启动的隧道：
//   - names 为空或含 "all"：返回全部启用隧道；
//   - 否则按名字精确匹配，不存在的名字告警跳过、已停用的名字告警跳过；
//   - 显式指定但一条都匹配不到时返回 errNoSelectedTunnels。
func resolveTunnels(st *store.Store, names []string) ([]*store.Tunnel, error) {
	all, err := st.ListTunnels()
	if err != nil {
		return nil, fmt.Errorf("failed to read the database: %w", err)
	}

	if isAllNames(names) {
		var out []*store.Tunnel
		for _, t := range all {
			if t.Enabled {
				out = append(out, t)
			}
		}
		return out, nil
	}

	byName := make(map[string]*store.Tunnel, len(all))
	for _, t := range all {
		byName[t.Name] = t
	}
	seen := map[string]bool{}
	var out []*store.Tunnel
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		t, ok := byName[n]
		if !ok {
			fmt.Printf("Warning: tunnel %q does not exist, skipping\n", n)
			continue
		}
		if !t.Enabled {
			fmt.Printf("Warning: tunnel %q is disabled, skipping\n", n)
			continue
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, errNoSelectedTunnels
	}
	return out, nil
}

// isAllNames 报告名称列表是否表示「全部」：为空或含 "all"。
func isAllNames(names []string) bool {
	if len(names) == 0 {
		return true
	}
	for _, n := range names {
		if strings.EqualFold(n, "all") {
			return true
		}
	}
	return false
}

func modeDescription(mode string) string {
	if mode == ModeTun {
		return "TUN tunnel + port forwards"
	}
	return "port forwards only"
}

func procPid(p *tun2socks.Process) int {
	if p == nil {
		return 0
	}
	return p.Pid()
}
