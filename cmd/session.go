package cmd

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/daemon"
	"github.com/Omoinemie/sshtun/internal/forwarder"
	"github.com/Omoinemie/sshtun/internal/logging"
	"github.com/Omoinemie/sshtun/internal/routing"
	"github.com/Omoinemie/sshtun/internal/socks5"
	"github.com/Omoinemie/sshtun/internal/sshclient"
	"github.com/Omoinemie/sshtun/internal/store"
	tc "github.com/Omoinemie/sshtun/internal/traffic"
	"github.com/Omoinemie/sshtun/internal/tun2socks"
)

// tunnelSession 承载单条隧道的全部运行时资源，彼此完全独立。
type tunnelSession struct {
	name string
	// uid 是隧道的稳定标识（改名不变），写入运行状态供界面按 UID 定位。
	uid       string
	cfg       *config.Config
	mode      string
	cli       *sshclient.Client
	socks     *socks5.Server
	socksLn   net.Listener
	socksAddr string
	proc      *tun2socks.Process
	entries   []routing.RouteEntry
	mgr       *forwarder.Manager
	// iface 为该隧道 TUN 网卡名（未启用 TUN 时为空）。
	iface string
	// ctr 统计经该隧道 SSH 通道搬运的字节（TUN 经 SOCKS5、端口转发经转发管道）。
	ctr *tc.Counter
}

// startTunnel 连接一条隧道并启动其独立的 SOCKS5 / tun2socks / 路由 / 端口转发。
// mode=ModeTun 时，若该隧道配置了路由则额外建立 TUN 分流；否则只做端口转发。
func startTunnel(name string, uid string, cfg *config.Config, mode string, saver CredentialSaver) (*tunnelSession, error) {
	s := &tunnelSession{name: name, uid: uid, cfg: cfg, mode: mode}
	ctr := &tc.Counter{}
	s.ctr = ctr
	// 流量统计在 SSH 通道层采集：TUN 流量经 SOCKS5、端口转发经转发管道，
	// 统一记入该隧道的计数器（详见 stats.go）。
	count := func(up, down int64) {
		ctr.AddUp(up)
		ctr.AddDown(down)
	}

	cli := sshclient.New(cfg)
	if isInteractive() {
		cli.PromptHostKey = interactiveHostKey()
	}
	// 经隧道拨号统一包装错误：把对端 sshd 的策略拒绝（如禁用 TCP 转发）
	// 翻译成可执行的排查建议，避免只看到 "administratively prohibited" 这类天书。
	dial := func(network, addr string) (net.Conn, error) {
		conn, err := cli.Dial(network, addr)
		if err != nil {
			return nil, sshclient.ExplainDialError(addr, err)
		}
		return conn, nil
	}
	mgr := forwarder.NewManager(cfg, dial, cli.ListenRemote, logging.Info)
	mgr.Count = count
	cli.OnReconnect = func() {
		logging.Warn("SSH reconnected, rebuilding the remote forwards", "tunnel", name)
		if err := mgr.RebuildRemote(); err != nil {
			if mode == ModeTun {
				logging.Warn("not all remote forwards could be rebuilt (the local proxy and routes are unaffected)", "tunnel", name, "err", err)
			} else {
				logging.Error("failed to rebuild the remote forwards", "tunnel", name, "err", err)
			}
		}
	}

	if err := connectWithPassword(cfg, cli, saver); err != nil {
		return nil, err
	}
	s.cli = cli
	s.mgr = mgr
	logging.Info("SSH connected", "tunnel", name, "endpoint", cfg.SSHEndpoint(), "user", cfg.SSH.User)

	// SOCKS5：仅监听回环，端口由内核自动分配（每条隧道独立的自用动态代理）。
	// 日志按隧道标记/归属（带 tunnel 字段便于按隧道筛选）；流量统计另行采集该隧道
	// TUN 网卡接口的内核计数（见 stats.go），与 SOCKS5 转发路径无关。
	logf := func(format string, args ...any) { logging.Info(fmt.Sprintf(format, args...), "tunnel", name) }
	socks := &socks5.Server{
		Dial:   dial,
		Logger: logf,
		Debug:  func(format string, args ...any) { logging.Debug(fmt.Sprintf(format, args...), "tunnel", name) },
		Count:  count,
	}
	socksLn, err := net.Listen("tcp", socks5.ListenAddr)
	if err != nil {
		s.Stop()
		return nil, fmt.Errorf("failed to listen on the SOCKS5 port: %w", err)
	}
	s.socks = socks
	s.socksLn = socksLn
	s.socksAddr = socksLn.Addr().String()
	socksErr := make(chan error, 1)
	go func() { socksErr <- socks.Serve(socksLn) }()
	select {
	case err := <-socksErr:
		s.Stop()
		return nil, fmt.Errorf("failed to start the SOCKS5 server: %w", err)
	case <-time.After(500 * time.Millisecond):
	}
	logging.Info("SOCKS5 listening", "tunnel", name, "addr", s.socksAddr)

	// tun2socks + 路由：仅当启用 TUN 模式且该隧道配置了路由时才建立。
	if mode == ModeTun {
		if len(cfg.Tun.Routes) == 0 && len(cfg.Tun.Bypass) == 0 {
			logging.Warn("the tunnel has no route, skipping the TUN device (only SOCKS5 and port forwards are kept)", "tunnel", name)
		} else {
			if err := s.startTun(); err != nil {
				s.Stop()
				return nil, err
			}
		}
	}

	// 端口转发。本地转发失败是本机绑定问题，直接失败；远程转发被拒时 TUN 模式下仅告警。
	if err := mgr.StartLocal(); err != nil {
		s.Stop()
		return nil, err
	}
	if err := mgr.StartRemote(); err != nil {
		if mode == ModeTun {
			logging.Warn("not all remote forwards could be established (the local proxy and routes are unaffected)", "tunnel", name, "err", err)
		} else {
			s.Stop()
			return nil, err
		}
	}
	traffic.register(name, ctr)
	return s, nil
}

// startTun 启动该隧道的 tun2socks 并配置地址/路由。
func (s *tunnelSession) startTun() error {
	bin, err := tun2socks.Find(s.cfg)
	if err != nil {
		return err
	}
	device := routing.DeviceArg(s.cfg.Tun.Name)
	// 重启场景下旧 wintun 适配器需先释放，同名新适配器才能创建成功。
	if !routing.WaitGone(device, 3*time.Second) {
		logging.Warn("the previous TUN adapter has not been released yet, trying to start anyway", "tunnel", s.name, "device", device)
	}
	logging.Info("starting tun2socks", "tunnel", s.name, "bin", bin, "device", device)
	proc, err := tun2socks.Start(s.cfg, bin, device, "socks5://"+s.socksAddr)
	if err != nil {
		return err
	}
	s.proc = proc
	logging.Info("tun2socks started", "tunnel", s.name, "pid", proc.Pid())

	// 保护路由需要 SSH 服务器的真实地址：优先用已连接对端 IP。
	sshHost := s.cli.PeerIP()
	if sshHost == "" {
		sshHost = s.cfg.SSH.Host
	}
	entries, err := routing.Setup(s.cfg, sshHost)
	if err != nil {
		return err
	}
	s.entries = entries
	s.iface = s.cfg.Tun.Name
	logging.Info("routes configured", "tunnel", s.name, "count", len(entries))
	return nil
}

// waitErr 返回该隧道 tun2socks 退出错误的通道；未启用 TUN 时返回 nil。
func (s *tunnelSession) waitErr() <-chan error {
	if s.proc == nil {
		return nil
	}
	ch := make(chan error, 1)
	go func() { ch <- s.proc.Wait() }()
	return ch
}

// stateInfo 汇总该隧道用于状态持久化的资源（含累计流量与实时速率，
// 供跨进程统计展示；速率由本进程采样器计算后随状态一并落盘）。
func (s *tunnelSession) stateInfo() daemon.TunnelState {
	st := daemon.TunnelState{
		Name:         s.name,
		UID:          s.uid,
		Tun2socksPid: procPid(s.proc),
		Iface:        s.iface,
		Listen:       s.socksAddr,
		Routes:       s.entries,
	}
	// 记录 SSH 实际连接的对端 IP（v4/v6），界面在 SSH 端点下方展示。
	if s.cli != nil {
		st.PeerIP = s.cli.PeerIP()
	}
	if s.ctr != nil {
		st.Up, st.Down = s.ctr.Up(), s.ctr.Down()
		st.UpSpeed, st.DownSpeed, _ = traffic.speed(s.name)
	}
	return st
}

// Stop 释放该隧道的全部资源。
func (s *tunnelSession) Stop() {
	traffic.unregister(s.name)
	if s.mgr != nil {
		s.mgr.Close()
	}
	if s.socks != nil {
		_ = s.socks.Close()
	}
	if s.socksLn != nil {
		_ = s.socksLn.Close()
	}
	if s.proc != nil {
		_ = s.proc.Stop()
	}
	if len(s.entries) > 0 {
		routing.Teardown(s.entries, s.cfg.Tun.Name)
	}
	if s.cli != nil {
		_ = s.cli.Close()
	}
}

// dbSaver 把认证重试时更新的凭据写回数据库。
type dbSaver struct {
	st   *store.Store
	name string
}

func (d dbSaver) SaveUser(user string) error { return d.st.UpdateUser(d.name, user) }

func (d dbSaver) SavePassword(enc string) error { return d.st.UpdatePassword(d.name, enc) }

// validateUniqueTunnels 校验各隧道的 TUN 接口名与地址互不冲突（否则路由无法区分归属）。
func validateUniqueTunnels(list []*store.Tunnel) error {
	byName := map[string]string{}
	byAddr := map[string]string{}
	var errs []error
	for _, t := range list {
		if prev, ok := byName[t.TunName]; ok {
			errs = append(errs, fmt.Errorf("tun_name of tunnel %q duplicates %q: %s", t.Name, prev, t.TunName))
		} else {
			byName[t.TunName] = t.Name
		}
		if prev, ok := byAddr[t.TunAddress]; ok {
			errs = append(errs, fmt.Errorf("tun_address of tunnel %q duplicates %q: %s", t.Name, prev, t.TunAddress))
		} else {
			byAddr[t.TunAddress] = t.Name
		}
	}
	return errors.Join(errs...)
}
