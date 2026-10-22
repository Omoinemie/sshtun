// Package sshclient 封装 SSH 连接：拨号、认证、保活与自动重连。
package sshclient

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/hostkey"
	"github.com/Omoinemie/sshtun/internal/logging"
)

// HostKeyPrompter 在主机密钥未被信任时被调用，返回是否接受该主机。
// 返回 true 时调用方会把密钥写入信任存储。
type HostKeyPrompter func(address string, key ssh.PublicKey, status hostkey.Status) (bool, error)

// Client 是一个支持自动重连的 SSH 客户端。
// 所有 Dial/Listen 调用通过当前活跃连接执行；断线后台自动重建。
type Client struct {
	cfg *config.Config

	mu     sync.RWMutex
	conn   *ssh.Client
	closed bool
	// connDone 是当前连接的结束信号：连接被替换/关闭时关闭它，
	// 使该连接上的 keepalive 协程立即退出，避免重连后旧协程堆积。
	connDone chan struct{}

	// peerIP 是最近一次成功连接对端的 IP，供路由保护使用
	// （见 routing.Setup：需要真实对端地址来判断地址族并下 /32 保护路由）。
	peerIP string

	// OnReconnect 在每次成功重连后被调用（用于重建远端转发等）。
	OnReconnect func()

	// PromptHostKey 非空时，未受信任的主机会先询问用户；
	// 为空则表示不允许交互，未受信任的主机将直接导致连接失败。
	PromptHostKey HostKeyPrompter

	// onConnectionLost 由内部使用，避免重连循环与外部通知重复。
	stopCh chan struct{}
}

// New 创建客户端（未连接）。
func New(cfg *config.Config) *Client {
	return &Client{cfg: cfg, stopCh: make(chan struct{})}
}

// Connect 建立首次连接；失败返回错误。
func (c *Client) Connect() error {
	client, err := c.dial()
	if err != nil {
		return err
	}
	done := make(chan struct{})
	c.mu.Lock()
	c.conn = client
	c.connDone = done
	c.mu.Unlock()

	go c.keepaliveLoop(client, done)
	go c.watchLoop()
	return nil
}

// authErrText 是 x/crypto/ssh 在对端拒绝认证时返回的错误文本。
const authErrText = "unable to authenticate"

// IsAuthError 报告 err 是否为「已连上但对端拒绝认证（账号或密码不被接受）」。
// 网络层失败（拨号不通、超时等）不算认证错误。
func IsAuthError(err error) bool {
	return err != nil && strings.Contains(err.Error(), authErrText)
}

// 对端拒绝通道/目标不可达时的错误文本（x/crypto/ssh 的 channel open failure 原因码）。
const (
	// prohibitedText：SSH_OPEN_ADMINISTRATIVELY_PROHIBITED —— 对端按策略拒绝建立通道。
	// 常见于对端 sshd 的 AllowTcpForwarding no / DisableForwarding yes / PermitOpen 不匹配。
	prohibitedText = "administratively prohibited"
	// connectFailedText：SSH_OPEN_CONNECT_FAILED —— 通道被允许，但对端连不上目标。
	connectFailedText = "connect failed"
)

// ErrForwardingProhibited 表示对端 sshd 按策略拒绝建立转发通道。
// 常见原因：对端 AllowTcpForwarding no / DisableForwarding yes / PermitOpen 不匹配
// （sshd_config.d/*.conf 的优先级高于主 sshd_config）。
var ErrForwardingProhibited = errors.New("the remote sshd refused to open a forwarding channel (administratively prohibited): " +
	"run 'sshd -T | grep -Ei 'allowtcpforwarding|permitopen|disableforwarding' on the remote host; AllowTcpForwarding must be yes")

// IsForwardingProhibited 报告 err 是否为「对端按策略拒绝建立转发通道」。
func IsForwardingProhibited(err error) bool {
	return err != nil && strings.Contains(err.Error(), prohibitedText)
}

// ExplainDialError 为「经隧道拨号失败」补充可执行的排查建议：
//   - 对端按策略拒绝通道（administratively prohibited）：多因对端 sshd 禁用了 TCP 转发；
//   - 通道被允许但对端连不上目标（connect failed）：属对端到目标的路由/防火墙问题。
//
// 原错误以 %w 包装，调用方仍可用 errors.Is/As 判断。
func ExplainDialError(target string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case IsForwardingProhibited(err):
		return fmt.Errorf("%w\n  troubleshooting suggestions:\n"+
			"    1) run 'sshd -T | grep -Ei 'allowtcpforwarding|permitopen|disableforwarding' on the remote host; AllowTcpForwarding must be yes\n"+
			"    2) note that /etc/ssh/sshd_config.d/*.conf on the remote host takes precedence over the main sshd_config (the first effective value of a keyword wins)\n"+
			"    3) reproduce it with an OpenSSH client: ssh -v -L 0:%s -N <user>@<host>", err, target)
	case strings.Contains(err.Error(), connectFailedText):
		return fmt.Errorf("%w\n  troubleshooting suggestions: the channel was allowed, but the remote host cannot reach the target; check the routing and firewall on the remote host", err)
	default:
		return err
	}
}

// ProbeForwarding 探测对端是否允许建立 TCP 转发通道（direct-tcpip）。
//
// 做法：尝试打开一条到 target 的通道。target 通常取对端本机几乎不会有监听的端口
// （如 127.0.0.1:1）：通道被允许但目标不可达时对端返回 "connect failed"，
// 说明转发能力正常；被策略拒绝时返回 "administratively prohibited"。
// 返回 nil 表示对端允许 TCP 转发。
func (c *Client) ProbeForwarding(target string) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return errors.New("the SSH connection is unavailable (it may be reconnecting)")
	}
	cn, err := conn.Dial("tcp", target)
	if err == nil {
		_ = cn.Close()
		return nil
	}
	switch {
	case IsForwardingProhibited(err):
		return fmt.Errorf("%w: %v", ErrForwardingProhibited, err)
	case strings.Contains(err.Error(), connectFailedText):
		// 通道已被允许，仅探测目标不可达 → 转发可用。
		return nil
	default:
		return err
	}
}

// dial 按配置建立一条新的 SSH 连接。
func (c *Client) dial() (*ssh.Client, error) {
	authMethods, err := c.authMethods()
	if err != nil {
		return nil, err
	}
	hk, err := c.hostKeyCallback()
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(c.cfg.SSH.ConnectTimeout) * time.Second
	d := net.Dialer{Timeout: timeout}
	nc, err := d.Dial("tcp", c.cfg.SSHEndpoint())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", c.cfg.SSHEndpoint(), err)
	}
	cc := &ssh.ClientConfig{
		User:            c.cfg.SSH.User,
		Auth:            authMethods,
		HostKeyCallback: hk,
		Timeout:         timeout,
	}
	client, chans, reqs, err := ssh.NewClientConn(nc, c.cfg.SSHEndpoint(), cc)
	if err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("SSH handshake/authentication failed: %w", err)
	}
	go ssh.DiscardRequests(reqs)
	_ = chans // 不接受服务端主动打开的通道
	if ta, ok := nc.RemoteAddr().(*net.TCPAddr); ok {
		c.mu.Lock()
		c.peerIP = ta.IP.String()
		c.mu.Unlock()
	}
	return ssh.NewClient(client, chans, reqs), nil
}

// PeerIP 返回最近一次成功连接对端的 IP；未连接或无法解析时返回空串。
func (c *Client) PeerIP() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.peerIP
}

func (c *Client) authMethods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	switch c.cfg.SSH.Auth {
	case "password":
		methods = append(methods, ssh.Password(c.cfg.SSH.Password))
	case "key":
		key, err := os.ReadFile(c.cfg.SSH.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read the private key %s: %w", c.cfg.SSH.KeyFile, err)
		}
		var signer ssh.Signer
		if c.cfg.SSH.KeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(c.cfg.SSH.KeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(key)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse the private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	default:
		return nil, fmt.Errorf("unsupported authentication method: %s", c.cfg.SSH.Auth)
	}
	return methods, nil
}

// hostKeyCallback 依据配置构造主机密钥校验回调：
//   - none: 跳过校验（不安全，仅适用于可信内网）；
//   - accept-new: 首次连接自动信任并写入信任存储，密钥变更时拒绝（防 MITM）；
//   - strict（含 ask）: 必须已在信任存储中；未信任时若有交互提示器则询问并写入，否则失败。
func (c *Client) hostKeyCallback() (ssh.HostKeyCallback, error) {
	mode, path := c.hostKeySettings()
	if mode == "none" {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	if path == "" {
		path = defaultKnownHostsPath(c.cfg.Path)
	}
	addr := c.cfg.SSHEndpoint()
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		status, err := hostkey.Check(path, addr, key)
		if err != nil {
			return err
		}
		if status == hostkey.StatusTrusted {
			return nil
		}
		// accept-new：仅对「首次出现」的主机自动信任；密钥变更仍按可疑处理。
		if mode == "accept-new" && status == hostkey.StatusUnknown {
			if aerr := hostkey.Add(path, addr, key); aerr != nil {
				return fmt.Errorf("failed to write the trust store: %w", aerr)
			}
			logging.Info("first connection, the host has been trusted automatically", "host", addr, "path", path, "fingerprint", hostkey.Fingerprint(key))
			return nil
		}
		if c.PromptHostKey == nil {
			if status == hostkey.StatusChanged {
				return fmt.Errorf("the host key of %s has changed (new fingerprint %s), the connection was rejected; update %s after confirming", addr, hostkey.Fingerprint(key), path)
			}
			return fmt.Errorf("host %s is not trusted (no record in %s and no interactive prompt is available); run in the foreground to confirm, or use ssh-keyscan first", addr, path)
		}
		accept, perr := c.PromptHostKey(addr, key, status)
		if perr != nil {
			return perr
		}
		if !accept {
			return fmt.Errorf("the user did not confirm trusting host %s, the connection was cancelled", addr)
		}
		if aerr := hostkey.Add(path, addr, key); aerr != nil {
			return fmt.Errorf("failed to write the trust store: %w", aerr)
		}
		logging.Info("the host has been trusted and written", "host", addr, "path", path, "fingerprint", hostkey.Fingerprint(key))
		return nil
	}, nil
}

// hostKeySettings 返回校验模式与信任存储路径。
// 正常路径下 ResolveSSHPaths 已写入 HostKeyMode；未解析时（例如测试直接构造配置）按原值推断。
func (c *Client) hostKeySettings() (mode, path string) {
	raw := strings.TrimSpace(c.cfg.SSH.HostKey)
	if c.cfg.SSH.HostKeyMode != "" {
		if raw == "none" || c.cfg.SSH.HostKeyMode == "none" {
			return "none", ""
		}
		return c.cfg.SSH.HostKeyMode, raw
	}
	switch raw {
	case "", "none":
		return "none", ""
	case "accept-new":
		return "accept-new", ""
	case "ask", "strict":
		return "strict", ""
	default:
		return "strict", raw
	}
}

// defaultKnownHostsPath 在未指定信任存储路径时给出默认位置。
func defaultKnownHostsPath(configPath string) string {
	if configPath != "" {
		return filepath.Join(filepath.Dir(configPath), "known_hosts")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".ssh", "sshtun_known_hosts")
	}
	return "known_hosts"
}

// keepaliveLoop 周期发送 keepalive 请求；连接被替换或连续失败则退出。
// done 在对应连接被关闭/替换时关闭，保证重连后不会残留旧连接的协程。
func (c *Client) keepaliveLoop(client *ssh.Client, done chan struct{}) {
	ka := c.cfg.SSH.Keepalive
	if ka <= 0 {
		return
	}
	t := time.NewTicker(time.Duration(ka) * time.Second)
	defer t.Stop()
	misses := 0
	for {
		select {
		case <-c.stopCh:
			return
		case <-done:
			return
		case <-t.C:
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				misses++
				if misses >= 2 {
					return // watchLoop 检测到断开后重连
				}
				continue
			}
			misses = 0
		}
	}
}

// watchLoop 监视当前连接，断开后自动重连。
func (c *Client) watchLoop() {
	backoff := time.Second
	for {
		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()
		if conn == nil {
			return
		}
		waitErrCh := make(chan error, 1)
		go func() {
			waitErrCh <- conn.Wait() // 阻塞直到连接关闭
		}()

		select {
		case <-c.stopCh:
			return
		case <-waitErrCh:
		}

		c.mu.Lock()
		if c.closed || c.conn != conn {
			c.mu.Unlock()
			return
		}
		c.conn = nil
		oldDone := c.connDone
		c.connDone = nil
		c.mu.Unlock()
		if oldDone != nil {
			close(oldDone) // 停止旧连接的 keepalive 协程
		}

		// 自动重连
		for {
			select {
			case <-c.stopCh:
				return
			default:
			}
			client, err := c.dial()
			if err == nil {
				done := make(chan struct{})
				c.mu.Lock()
				if c.closed {
					client.Close()
					c.mu.Unlock()
					return
				}
				c.conn = client
				c.connDone = done
				c.mu.Unlock()
				go c.keepaliveLoop(client, done)
				if c.OnReconnect != nil {
					go c.OnReconnect()
				}
				backoff = time.Second
				break
			}
			if IsAuthError(err) {
				logging.Error("SSH reconnection failed: the remote host rejected the authentication (the password may have changed), run it in the foreground again to enter the new password", "retry_in", backoff.String())
			} else {
				logging.Warn("SSH reconnection failed", "err", err, "retry_in", backoff.String())
			}
			select {
			case <-c.stopCh:
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > 5*time.Minute {
				backoff = 5 * time.Minute
			}
		}
	}
}

// Dial 经 SSH 打开到 target(host:port) 的 TCP 通道。
func (c *Client) Dial(network, addr string) (net.Conn, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return nil, errors.New("the SSH connection is unavailable (it may be reconnecting)")
	}
	return conn.Dial(network, addr)
}

// ListenRemote 在 SSH 服务端申请监听（用于 -R）。
func (c *Client) ListenRemote(addr string) (net.Listener, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return nil, errors.New("the SSH connection is unavailable (it may be reconnecting)")
	}
	return conn.Listen("tcp", addr)
}

// Close 关闭当前连接并停止后台协程。
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.stopCh)
	if c.connDone != nil {
		close(c.connDone)
		c.connDone = nil
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

var _ io.Closer = (*Client)(nil)
