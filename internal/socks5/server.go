// Package socks5 实现最小 SOCKS5 服务端（RFC1928，CONNECT），上游为 SSH 隧道。
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Omoinemie/sshtun/internal/traffic"
)

// ListenAddr 是 SOCKS5 的本地监听地址：仅回环，端口填 0 交由内核分配，
// 避免与其它程序（例如已在监听 1080 的代理）冲突。实际端口在运行时确定，
// 调用方用 net.Listen(ListenAddr, ...) 取得 listener，把 ln.Addr() 作为
// tun2socks 的上游地址，再把 listener 交给 Serve。
const ListenAddr = "127.0.0.1:0"

// DialFunc 建立到目标地址的上游连接。
type DialFunc func(network, addr string) (net.Conn, error)

// Server 是一个 SOCKS5(CONNECT) 服务端。
type Server struct {
	// Dial 上游拨号函数（经 SSH）。
	Dial DialFunc
	// ConnTimeout 单条连接的空闲超时，0 表示不限。
	ConnTimeout time.Duration
	// Logger 可选日志函数，如 slog.Info 的包装。
	Logger func(format string, args ...any)
	// Debug 可选调试日志函数；请求级噪声（如 tun2socks 探测、UDP ASSOCIATE
	// 被拒）走这里，避免刷屏。nil 时静默。
	Debug func(format string, args ...any)
	// Count 可选的流量计数回调：up 为客户端→上游（上传），down 为上游→客户端（下载）。
	// nil 时不计数。
	Count func(up, down int64)

	ln     net.Listener
	mu     sync.Mutex
	closed bool
}

// Serve 在已有 listener 上开始服务，阻塞直到 listener 关闭。
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	s.ln = ln
	s.mu.Unlock()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if s.Logger != nil {
				s.Logger("SOCKS5 accept error: %v", err)
			}
			continue
		}
		go s.handleConn(conn)
	}
}

// Close 关闭监听；与 Serve 并发调用是安全的（先 Close 后 Serve 会立即关闭传入的 listener）。
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger(format, args...)
	}
}

func (s *Server) debugf(format string, args ...any) {
	if s.Debug != nil {
		s.Debug(format, args...)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	if s.ConnTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.ConnTimeout))
	}
	defer func() {
		if s.ConnTimeout > 0 {
			_ = conn.SetDeadline(time.Time{})
		}
	}()

	if err := s.handshake(conn); err != nil {
		s.logf("SOCKS5 handshake failed %s: %v", conn.RemoteAddr(), err)
		return
	}

	target, err := readConnectRequest(conn)
	if err != nil {
		// UDP ASSOCIATE 被拒属预期噪声（tun2socks 探测 UDP），静默；
		// 其余请求错误保留调试日志便于排查。
		if !errors.Is(err, errUDPUnsupported) {
			s.debugf("SOCKS5 CONNECT request error %s: %v", conn.RemoteAddr(), err)
		}
		return
	}

	upstream, err := s.Dial("tcp", target)
	if err != nil {
		s.logf("failed to connect to %s through the tunnel: %v", target, err)
		_ = reply(conn, replyHostUnreachable)
		return
	}
	defer upstream.Close()

	if err := reply(conn, replySuccess); err != nil {
		return
	}
	s.logf("tunnel %s -> %s", conn.RemoteAddr(), target)

	if s.ConnTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.ConnTimeout))
		_ = upstream.SetDeadline(time.Now().Add(s.ConnTimeout))
	}
	pipe(conn, upstream, s.Count)
}

// handshake 完成方法协商：仅支持无需认证。
func (s *Server) handshake(conn net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 5 {
		return fmt.Errorf("unsupported protocol version: %d", head[0])
	}
	nMethods := int(head[1])
	if nMethods == 0 || nMethods > 32 {
		return errors.New("the method list is empty or too long")
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		// 0xFF 表示无可接受方法
		_, _ = conn.Write([]byte{5, 0xFF})
		return errors.New("the client does not support the no-authentication method")
	}
	_, err := conn.Write([]byte{5, 0x00})
	return err
}

// 目标地址解析。
const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

// errUDPUnsupported 标记 SOCKS5 UDP ASSOCIATE 被拒。SSH 隧道只能承载 TCP，
// 而 tun2socks 会对配置网段内的 UDP 流量反复探测，属确定性预期噪声，
// 调用方据此静默处理，不再逐条记录。
var errUDPUnsupported = errors.New("UDP ASSOCIATE is not supported (the SSH tunnel only supports TCP)")

func readConnectRequest(conn net.Conn) (string, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	if head[0] != 5 {
		return "", fmt.Errorf("wrong request version: %d", head[0])
	}
	cmd := head[1]
	if cmd != 1 { // 1=CONNECT
		if cmd == 3 {
			_ = reply(conn, replyCmdNotSupported)
			return "", errUDPUnsupported
		}
		_ = reply(conn, replyCmdNotSupported)
		return "", fmt.Errorf("unsupported command: %d", cmd)
	}
	switch head[3] {
	case atypIPv4:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		ip := net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
		return net.JoinHostPort(ip, strconv.Itoa(int(binary.BigEndian.Uint16(buf[4:6])))), nil
	case atypIPv6:
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		ip := net.IP(buf[:16]).String()
		return net.JoinHostPort(ip, strconv.Itoa(int(binary.BigEndian.Uint16(buf[16:18])))), nil
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return "", err
		}
		host := make([]byte, l[0])
		if _, err := io.ReadFull(conn, host); err != nil {
			return "", err
		}
		buf := make([]byte, 2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		return net.JoinHostPort(strings.TrimSpace(string(host)), strconv.Itoa(int(binary.BigEndian.Uint16(buf)))), nil
	default:
		_ = reply(conn, replyAddrTypeNotSupported)
		return "", fmt.Errorf("unsupported address type: %d", head[3])
	}
}

// 回复码。
const (
	replySuccess              = 0
	replyHostUnreachable      = 4
	replyCmdNotSupported      = 7
	replyAddrTypeNotSupported = 8
)

func reply(conn net.Conn, code byte) error {
	// VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
	_, err := conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

// pipe 双向拷贝；任一方向结束后主动关闭两端，确保另一方向的阻塞 Read 立即返回
// （SSH 通道包装的 net.Conn 不能以 deadline 打断读取，必须用 Close）。
// a 为本地客户端连接、b 为上游（经 SSH）连接，count 为可选的流量计数回调：
// a→b 记为上传，b→a 记为下载。计数经 traffic.Writer 逐块累计，
// 使传输期间累计值与实时速率即可反映流量，而非等连接结束才记账。
func pipe(a, b net.Conn, count func(up, down int64)) {
	errCh := make(chan struct{}, 2)
	go func() {
		dst := io.Writer(b)
		if count != nil {
			dst = &traffic.Writer{W: b, Add: func(n int64) { count(n, 0) }}
		}
		_, _ = io.Copy(dst, a)
		errCh <- struct{}{}
	}()
	go func() {
		dst := io.Writer(a)
		if count != nil {
			dst = &traffic.Writer{W: a, Add: func(n int64) { count(0, n) }}
		}
		_, _ = io.Copy(dst, b)
		errCh <- struct{}{}
	}()
	<-errCh
	_ = a.Close()
	_ = b.Close()
	<-errCh
}
