// Package forwarder 实现 SSH 本地转发(-L)与远程转发(-R)。
// 通过注入 Dial/Listen 函数与 SSH 实现解耦，断线重连由上层驱动。
package forwarder

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/traffic"
)

// DialFunc 建立经隧道到 target(host:port) 的连接。
type DialFunc func(network, addr string) (net.Conn, error)

// ListenFunc 在 SSH 服务端申请监听（用于 -R）。
type ListenFunc func(addr string) (net.Listener, error)

// Manager 管理所有转发规则的生命周期。
type Manager struct {
	cfg      *config.Config
	dial     DialFunc
	listen   ListenFunc
	log      func(msg string, args ...any)
	locals   []net.Listener
	remotes  []*remoteForward
	mu       sync.Mutex
	stopped  bool
	stopOnce sync.Once
	stopCh   chan struct{}

	// Count 可选的流量计数回调（up 为本机→隧道远端，down 为反向）；nil 时不计数。
	// 端口转发不经过 TUN 网卡，流量统计只能在转发管道处采集。
	Count func(up, down int64)
}

// NewManager 创建转发管理器。log 为 nil 时静默。
func NewManager(cfg *config.Config, dial DialFunc, listen ListenFunc, log func(msg string, args ...any)) *Manager {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Manager{cfg: cfg, dial: dial, listen: listen, log: log, stopCh: make(chan struct{})}
}

// StartLocal 启动全部本地转发。
// 未显式指定监听地址时绑定 127.0.0.1（与 OpenSSH -L 语义一致），
// 避免把内网目标服务意外暴露到局域网。
func (m *Manager) StartLocal() error {
	for _, rule := range m.cfg.Forwards.Local {
		bind := rule.BindAddr
		if bind == "" {
			bind = "127.0.0.1"
		}
		addr := net.JoinHostPort(bind, fmt.Sprint(rule.BindPort))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			m.Close()
			return fmt.Errorf("failed to start the local forward %s: %w", rule.Raw, err)
		}
		m.mu.Lock()
		m.locals = append(m.locals, ln)
		m.mu.Unlock()
		go m.serveLocal(ln, rule)
		m.log("local forward established", "raw", rule.Raw, "listen", addr, "target", rule.Target)
	}
	return nil
}

func (m *Manager) serveLocal(ln net.Listener, rule config.ForwardRule) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-m.stopCh:
				return
			default:
			}
			m.log("local forward accept ended", "raw", rule.Raw, "err", err)
			return
		}
		go m.handleLocal(conn, rule)
	}
}

func (m *Manager) handleLocal(conn net.Conn, rule config.ForwardRule) {
	defer conn.Close()
	upstream, err := m.dial("tcp", rule.Target)
	if err != nil {
		m.log("local forward dial failed", "target", rule.Target, "err", err)
		return
	}
	defer upstream.Close()
	// conn 侧是本机客户端、upstream 侧是隧道远端：conn→upstream 记为上传。
	if err := pipe(conn, upstream, m.countUp, m.countDown); err != nil {
		m.log("local forward pipe error", "raw", rule.Raw, "err", err)
	}
}

// StartRemote 启动全部远程转发。单条被服务端拒绝不阻断其余规则，
// 返回聚合错误（全部成功时为 nil），由调用方决定是致命还是仅告警。
func (m *Manager) StartRemote() error {
	var errs []error
	for _, rule := range m.cfg.Forwards.Remote {
		if err := m.startRemote(rule); err != nil {
			errs = append(errs, fmt.Errorf("failed to start the remote forward %s: %w", rule.Raw, err))
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) startRemote(rule config.ForwardRule) error {
	// 显式给出监听地址：ssh -R 的默认语义是「仅监听服务端回环」，
	// 用 127.0.0.1 把这个语义写明；配 0.0.0.0 则表示申请通配（是否生效取决于服务端 GatewayPorts）。
	bind := rule.BindAddr
	if bind == "" {
		bind = "127.0.0.1"
	}
	listenAddr := net.JoinHostPort(bind, fmt.Sprint(rule.BindPort))
	ln, err := m.listen(listenAddr)
	if err != nil {
		if strings.Contains(err.Error(), "denied by peer") {
			return fmt.Errorf("%w\n  the remote forward was rejected by the server, usually due to server policy or a port conflict (not a configuration format issue); check on the server:\n"+
				"    1) sshd -T | grep -Ei 'allowtcpforwarding|permitlisten|gatewayports' (AllowTcpForwarding must be yes; if it is local, only -L is allowed and remote forwards are rejected)\n"+
				"    2) ss -ltnp | grep :%d (the port may already be in use)\n"+
				"    3) reproduce it with an OpenSSH client: ssh -v -R %d:%s -N <user>@<host>",
				err, rule.BindPort, rule.BindPort, rule.Target)
		}
		return err
	}
	m.mu.Lock()
	m.remotes = append(m.remotes, &remoteForward{rule: rule, ln: ln})
	m.mu.Unlock()
	go m.serveRemote(ln, rule)
	m.log("remote forward established", "raw", rule.Raw, "remote_listen", listenAddr, "target", rule.Target)
	return nil
}

func (m *Manager) serveRemote(ln net.Listener, rule config.ForwardRule) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-m.stopCh:
				return
			default:
			}
			return // 服务端断开时静默结束，由 RebuildRemote 重建
		}
		go m.handleRemote(conn, rule)
	}
}

func (m *Manager) handleRemote(conn net.Conn, rule config.ForwardRule) {
	defer conn.Close()
	local, err := net.Dial("tcp", rule.Target)
	if err != nil {
		m.log("remote forward failed to dial the local target", "target", rule.Target, "err", err)
		return
	}
	defer local.Close()
	// conn 侧来自隧道远端、local 侧是本机目标：conn→local 记为下载。
	if err := pipe(conn, local, m.countDown, m.countUp); err != nil {
		m.log("remote forward pipe error", "raw", rule.Raw, "err", err)
	}
}

// countUp / countDown 把两个方向的字节数送入可选的计数回调（nil 回调时静默）。
func (m *Manager) countUp(n int64) {
	if m.Count != nil {
		m.Count(n, 0)
	}
}

func (m *Manager) countDown(n int64) {
	if m.Count != nil {
		m.Count(0, n)
	}
}

// RebuildRemote 在 SSH 重连后重建远程转发（远端监听随断开失效）。
func (m *Manager) RebuildRemote() error {
	m.mu.Lock()
	old := m.remotes
	m.remotes = nil
	m.mu.Unlock()
	for _, o := range old {
		_ = o.ln.Close()
	}
	if len(m.cfg.Forwards.Remote) == 0 {
		return nil
	}
	return m.StartRemote()
}

// Close 停止全部转发。
func (m *Manager) Close() {
	m.stopOnce.Do(func() {
		m.mu.Lock()
		m.stopped = true
		locals := m.locals
		m.locals = nil
		remotes := m.remotes
		m.remotes = nil
		m.mu.Unlock()
		close(m.stopCh)
		for _, l := range locals {
			_ = l.Close()
		}
		for _, o := range remotes {
			_ = o.ln.Close()
		}
	})
}

type remoteForward struct {
	rule config.ForwardRule
	ln   net.Listener
}

// pipe 双向拷贝；任一方向结束后主动关闭两端，确保另一方向的阻塞 Read 立即返回
// （SSH 通道包装的 net.Conn 不支持以 deadline 打断读取，必须用 Close）。
// 因主动关闭而产生的 io.EOF / net.ErrClosed 属正常结束，不作为错误返回。
// aToB / bToA 为可选的字节数回调，由调用方按转发方向映射到上传/下载；
// 经 traffic.Writer 逐块累计，使传输期间累计值与实时速率即可反映流量。
func pipe(a, b net.Conn, aToB, bToA func(int64)) error {
	errCh := make(chan error, 2)
	go func() {
		dst := io.Writer(a)
		if bToA != nil {
			dst = &traffic.Writer{W: a, Add: bToA}
		}
		_, err := io.Copy(dst, b)
		errCh <- err
	}()
	go func() {
		dst := io.Writer(b)
		if aToB != nil {
			dst = &traffic.Writer{W: b, Add: aToB}
		}
		_, err := io.Copy(dst, a)
		errCh <- err
	}()
	first := <-errCh
	_ = a.Close()
	_ = b.Close()
	second := <-errCh
	if !benign(first) {
		return first
	}
	if !benign(second) {
		return second
	}
	return nil
}

// benign 判断错误是否只是「连接已关闭/读到末尾」这类正常收尾。
func benign(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}
