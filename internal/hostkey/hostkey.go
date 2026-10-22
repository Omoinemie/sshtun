// Package hostkey 实现主机密钥的信任存储（OpenSSH known_hosts 兼容）。
// 提供信任状态检查、指纹计算与条目写入/替换。
package hostkey

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Status 表示主机密钥相对信任存储的检查结果。
type Status int

const (
	// StatusTrusted 密钥已存在于信任存储且匹配。
	StatusTrusted Status = iota
	// StatusUnknown 宿主不在信任存储中（首次连接，可交互确认）。
	StatusUnknown
	// StatusChanged 宿主存在但密钥已变更（可能为中间人攻击）。
	StatusChanged
)

// String 返回状态的文字描述。
func (s Status) String() string {
	switch s {
	case StatusTrusted:
		return "trusted"
	case StatusUnknown:
		return "unknown"
	case StatusChanged:
		return "changed"
	default:
		return "unknown"
	}
}

// Fingerprint 返回 OpenSSH 风格的 SHA256 指纹（形如 SHA256:xx...）。
func Fingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// Check 检查 key 对 address（host:port）的信任状态。
// 信任存储文件不存在时视为空库，返回 StatusUnknown。
func Check(path, address string, key ssh.PublicKey) (Status, error) {
	cb, err := load(path)
	if err != nil {
		return StatusUnknown, err
	}
	if cb == nil {
		return StatusUnknown, nil
	}
	err = cb(address, remoteAddr(address), key)
	if err == nil {
		return StatusTrusted, nil
	}
	var kerr *knownhosts.KeyError
	if errors.As(err, &kerr) {
		if len(kerr.Want) == 0 {
			return StatusUnknown, nil
		}
		return StatusChanged, nil
	}
	return StatusUnknown, err
}

// Add 将 address 与 key 追加到信任存储；同宿主的旧条目会被替换（原子写）。
func Add(path, address string, key ssh.PublicKey) error {
	hostField := knownhosts.Normalize(address)
	newLine := knownhosts.Line([]string{address}, key)

	var kept []string
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		for _, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimRight(raw, "\r")
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				kept = append(kept, line)
				continue
			}
			// 已有同宿主条目（可能是变更前的密钥）一律替换。
			if hostPattern(line) == hostField {
				continue
			}
			kept = append(kept, line)
		}
	case os.IsNotExist(err):
		// 文件不存在则新建。
	default:
		return fmt.Errorf("failed to read %s: %w", path, err)
	}

	var sb strings.Builder
	for _, line := range kept {
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	sb.WriteString(newLine)
	sb.WriteByte('\n')

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("failed to create the directory %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("failed to update %s: %w", path, err)
	}
	return nil
}

// load 加载信任存储；文件不存在返回 (nil, nil)。
func load(path string) (ssh.HostKeyCallback, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("trust store %s is not readable: %w", path, err)
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return cb, nil
}

// remoteAddr 构造一个仅用于满足 knownhosts 内部 remote.String() 的占位地址。
func remoteAddr(address string) net.Addr {
	port := 22
	if _, portStr, err := net.SplitHostPort(address); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
}

// hostPattern 提取一行 known_hosts 的宿主字段（跳过 @marker）。
func hostPattern(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	if strings.HasPrefix(fields[0], "@") {
		if len(fields) < 2 {
			return ""
		}
		return fields[1]
	}
	return fields[0]
}
