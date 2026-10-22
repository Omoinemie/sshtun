package daemon

// 隧道锁：保证同一条隧道在同一时刻只被一个 sshtun 实例占用。
//
// 背景：TUN 设备（Windows 的 wintun 适配器）按名字唯一，前台 CLI、后台守护
// 进程、GUI 后端若同时启动同一条隧道，会各自创建同名适配器；后启动的一方会把
// 先启动一方的适配器当作「孤儿」删除，导致先启动的隧道静默失效。
//
// 实现：在状态目录下按隧道名建立锁文件，文件内容为持有者 pid：
//   - 锁文件不存在 → 以 O_EXCL 原子创建，占用成功；
//   - 持有者仍存活   → 占用失败，调用方应拒绝启动该隧道；
//   - 持有者已退出（进程被强杀，锁文件残留）→ 删除残留锁后接管。
//
// 锁在进程正常退出时释放；进程被强杀时锁文件残留，但持有者已死，下次启动会自动接管。

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrTunnelInUse 表示该隧道已被另一个存活实例占用。
var ErrTunnelInUse = errors.New("tunnel is already running in another instance")

// tunnelLockDir 是锁文件所在目录（位于状态目录下）。
const tunnelLockDir = "locks"

// stateDirOverride 仅供测试替换状态目录；为空时使用 StateDir()。
var stateDirOverride string

// lockStateDir 返回锁文件所在的状态目录。
func lockStateDir() (string, error) {
	if stateDirOverride != "" {
		return stateDirOverride, nil
	}
	return StateDir()
}

// TunnelLock 是一条隧道的占用锁。
type TunnelLock struct {
	// path 是锁文件路径。
	path string
	// pid 是持有者进程 pid。
	pid int
}

// AcquireTunnelLock 占用名为 name 的隧道锁。
//
// 成功返回锁对象；调用方应在隧道停止时调用 Release 释放。
// 隧道已被其它存活实例占用时返回包装了 ErrTunnelInUse 的错误。
func AcquireTunnelLock(name string) (*TunnelLock, error) {
	dir, err := lockStateDir()
	if err != nil {
		return nil, err
	}
	lockDir := filepath.Join(dir, tunnelLockDir)
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create the tunnel lock directory: %w", err)
	}
	path := filepath.Join(lockDir, lockFileName(name))
	pid := os.Getpid()

	for attempt := 0; attempt < 3; attempt++ {
		f, cerr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if cerr == nil {
			_, _ = fmt.Fprintf(f, "%d\n", pid)
			_ = f.Close()
			return &TunnelLock{path: path, pid: pid}, nil
		}
		if !os.IsExist(cerr) {
			return nil, fmt.Errorf("failed to create tunnel lock %s: %w", path, cerr)
		}
		holder, ok := readLockPid(path)
		switch {
		case ok && holder == pid:
			// 同一进程内重复占用（如控制通道重复启动同一隧道）：视为已持有。
			return &TunnelLock{path: path, pid: pid}, nil
		case ok && IsAlive(holder):
			return nil, fmt.Errorf("%w (holding process pid=%d), stop that instance first", ErrTunnelInUse, holder)
		}
		// 残留锁：持有者已退出，删除后重建。
		_ = os.Remove(path)
	}
	return nil, fmt.Errorf("failed to acquire the lock for tunnel %s, please retry later", name)
}

// Release 释放锁（删除锁文件）。可重复调用；锁已被其它进程接管时不做任何事。
func (l *TunnelLock) Release() {
	if l == nil || l.path == "" {
		return
	}
	if holder, ok := readLockPid(l.path); ok && holder != l.pid {
		return // 已被其它进程接管，不误删
	}
	_ = os.Remove(l.path)
}

// ReleaseTunnelLock 释放指定隧道的锁，用于外部清理场景（如 `sshtun stop`）。
// 持有者仍存活时不删除，避免误删其它实例的锁。
func ReleaseTunnelLock(name string) {
	dir, err := lockStateDir()
	if err != nil {
		return
	}
	path := filepath.Join(dir, tunnelLockDir, lockFileName(name))
	if holder, ok := readLockPid(path); ok && holder != os.Getpid() && IsAlive(holder) {
		return // 其它存活实例仍持有，不动
	}
	_ = os.Remove(path)
}

// TunnelLockHolder 返回指定隧道锁的持有者 pid 与其存活状态；
// 没有锁文件时 holder 为 0、alive 为 false。
func TunnelLockHolder(name string) (holder int, alive bool) {
	dir, err := lockStateDir()
	if err != nil {
		return 0, false
	}
	path := filepath.Join(dir, tunnelLockDir, lockFileName(name))
	pid, ok := readLockPid(path)
	if !ok {
		return 0, false
	}
	return pid, IsAlive(pid)
}

// readLockPid 读取锁文件中的 pid；文件缺失或内容非法时返回 (0, false)。
func readLockPid(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// lockFileName 由隧道名生成锁文件名：保留可读字符，并附名称哈希避免不同名字
// 清洗后撞到同一文件。
func lockFileName(name string) string {
	sum := sha256.Sum256([]byte(name))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	safe := b.String()
	if len(safe) > 32 {
		safe = safe[:32]
	}
	return fmt.Sprintf("%s-%s.lock", safe, hex.EncodeToString(sum[:4]))
}
