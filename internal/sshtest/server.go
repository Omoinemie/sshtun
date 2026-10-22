// Package sshtest 提供测试用的进程内 SSH 服务器：
// 支持 password 认证(test/test)、公钥认证(服务端授权的客户端密钥)、
// direct-tcpip(动态转发)、tcpip-forward/forwarded-tcpip(远程转发)。
package sshtest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Server 是测试 SSH 服务器。
type Server struct {
	Addr string

	ln net.Listener

	mu                sync.Mutex
	sconn             *ssh.ServerConn
	boundAddr         string
	lastRequestedPort uint32
	boundLn           net.Listener

	// clientKey 是服务端已授权的客户端私钥（供 key 认证测试）。
	clientKey ed25519.PrivateKey
}

// Start 启动服务器。direct-tcpip 目标直接 net.Dial 到真实地址。
// 认证：用户 test + 密码 test，或用户 test + 服务端授权的客户端密钥（见 WriteClientKey）。
func Start(t *testing.T) *Server {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成主机密钥失败: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("创建 signer 失败: %v", err)
	}
	cpub, cpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成客户端密钥失败: %v", err)
	}
	clientKey, err := ssh.NewPublicKey(cpub)
	if err != nil {
		t.Fatalf("转换客户端公钥失败: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == "test" && string(password) == "test" {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("认证失败")
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if conn.User() == "test" && bytes.Equal(key.Marshal(), clientKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("认证失败")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	s := &Server{Addr: ln.Addr().String(), ln: ln, clientKey: cpriv}
	go s.acceptLoop(cfg)
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

// WriteClientKey 将服务端已授权的客户端私钥写入 path，返回 path（用于 key 认证）。
func (s *Server) WriteClientKey(t *testing.T, path string) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(s.clientKey, "")
	if err != nil {
		t.Fatalf("序列化客户端私钥失败: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("写入客户端私钥失败: %v", err)
	}
	return path
}

func (s *Server) acceptLoop(cfg *ssh.ServerConfig) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c, cfg)
	}
}

func (s *Server) handleConn(c net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.sconn = sconn
	s.mu.Unlock()

	go func() {
		for req := range reqs {
			switch req.Type {
			case "tcpip-forward":
				addr, port := parseHostPortPayload(req.Payload)
				// 模拟 OpenSSH：申请绑定的地址必须先能解析并占用，失败即拒绝，
				// 客户端会收到 "ssh: tcpip-forward request denied by peer"。
				if addr == "" {
					addr = "127.0.0.1" // 服务端默认仅回环
				}
				ln, lerr := net.Listen("tcp", net.JoinHostPort(addr, fmt.Sprint(port)))
				if lerr != nil {
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
					continue
				}
				actualPort := uint32(ln.Addr().(*net.TCPAddr).Port)
				s.mu.Lock()
				s.boundAddr = addr
				s.lastRequestedPort = actualPort
				s.boundLn = ln
				s.mu.Unlock()
				reply := make([]byte, 4)
				binary.BigEndian.PutUint32(reply, actualPort)
				if req.WantReply {
					_ = req.Reply(true, reply)
				}
			case "cancel-tcpip-forward":
				s.mu.Lock()
				if s.boundLn != nil {
					_ = s.boundLn.Close()
					s.boundLn = nil
				}
				s.mu.Unlock()
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
	}()

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "direct-tcpip":
			target := parseDirectTarget(newChan.ExtraData())
			ch, _, err := newChan.Accept()
			if err != nil {
				continue
			}
			go s.pipeDirect(ch, target)
		default:
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

func (s *Server) pipeDirect(ch ssh.Channel, target string) {
	defer ch.Close()
	up, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer up.Close()
	go func() {
		_, _ = io.Copy(up, ch)
		_ = up.Close()
	}()
	_, _ = io.Copy(ch, up)
}

// TriggerForwardedConn 模拟服务端侧向客户端投递一条 forwarded-tcpip 连接（远程转发场景）。
// 返回服务端侧通道，可对其读写以与客户端转发的"本地目标"通信。
func (s *Server) TriggerForwardedConn(t *testing.T) ssh.Channel {
	t.Helper()
	s.mu.Lock()
	boundAddr := s.boundAddr
	port := s.lastRequestedPort
	sconn := s.sconn
	s.mu.Unlock()
	if sconn == nil {
		t.Fatal("SSH 连接未建立")
	}
	// boundAddr 必须与客户端申请监听时使用的地址完全一致（可能为空串），客户端据此匹配监听器
	payload := marshalForwardedPayload(boundAddr, port, "10.9.9.9", 12345)
	ch, _, err := sconn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		t.Fatalf("打开 forwarded-tcpip 通道失败: %v", err)
	}
	return ch
}

// ---- payload 编解码 ----

func parseHostPortPayload(payload []byte) (addr string, port uint32) {
	addr, payload = readString(payload)
	if len(payload) >= 4 {
		port = binary.BigEndian.Uint32(payload[:4])
	}
	return addr, port
}

func parseDirectTarget(extra []byte) string {
	addr, rest := readString(extra)
	var port uint32
	if len(rest) >= 4 {
		port = binary.BigEndian.Uint32(rest[:4])
	}
	return net.JoinHostPort(addr, fmt.Sprint(port))
}

func marshalForwardedPayload(boundAddr string, boundPort uint32, originAddr string, originPort uint32) []byte {
	var out []byte
	out = appendString(out, boundAddr)
	out = binary.BigEndian.AppendUint32(out, boundPort)
	out = appendString(out, originAddr)
	out = binary.BigEndian.AppendUint32(out, originPort)
	return out
}

func readString(b []byte) (string, []byte) {
	if len(b) < 4 {
		return "", nil
	}
	n := binary.BigEndian.Uint32(b[:4])
	if int(n)+4 > len(b) {
		return "", nil
	}
	return string(b[4 : 4+n]), b[4+n:]
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}
