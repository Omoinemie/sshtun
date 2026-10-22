package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// useTempStateDir 把锁文件目录指向临时目录，测试结束后还原。
func useTempStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := stateDirOverride
	stateDirOverride = dir
	t.Cleanup(func() { stateDirOverride = old })
	return dir
}

// writeLock 直接写入锁文件，用于构造「被他人占用」与「残留锁」两种状态。
func writeLock(t *testing.T, dir, name string, pid int) {
	t.Helper()
	lockDir := filepath.Join(dir, tunnelLockDir)
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		t.Fatalf("创建锁目录失败: %v", err)
	}
	path := filepath.Join(lockDir, lockFileName(name))
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatalf("写入锁文件失败: %v", err)
	}
}

func TestAcquireTunnelLock_Basic(t *testing.T) {
	dir := useTempStateDir(t)

	lock, err := AcquireTunnelLock("alpha")
	if err != nil {
		t.Fatalf("占用锁失败: %v", err)
	}
	holder, alive := TunnelLockHolder("alpha")
	if holder != os.Getpid() || !alive {
		t.Errorf("锁持有者应为当前进程, got holder=%d alive=%v", holder, alive)
	}
	lock.Release()

	if _, ok := TunnelLockHolder("alpha"); ok {
		t.Error("释放后不应再有锁持有者")
	}
	if _, err := os.Stat(filepath.Join(dir, tunnelLockDir, lockFileName("alpha"))); !os.IsNotExist(err) {
		t.Error("释放后锁文件应被删除")
	}
}

func TestAcquireTunnelLock_InUseByLiveProcess(t *testing.T) {
	dir := useTempStateDir(t)

	// 用父进程 pid 模拟「另一个存活实例」持有该隧道。
	other := os.Getppid()
	if other <= 0 || other == os.Getpid() {
		t.Skip("父进程 pid 不可用，跳过")
	}
	writeLock(t, dir, "beta", other)

	_, err := AcquireTunnelLock("beta")
	if err == nil {
		t.Fatal("被存活实例占用时应占用失败")
	}
	if !errors.Is(err, ErrTunnelInUse) {
		t.Errorf("应返回 ErrTunnelInUse, got %v", err)
	}
}

func TestAcquireTunnelLock_TakeOverStaleLock(t *testing.T) {
	dir := useTempStateDir(t)

	// 残留锁：持有者已退出（pid 不存在）。
	writeLock(t, dir, "gamma", 0x7FFFFFF0)

	lock, err := AcquireTunnelLock("gamma")
	if err != nil {
		t.Fatalf("残留锁应可被接管: %v", err)
	}
	defer lock.Release()
	holder, alive := TunnelLockHolder("gamma")
	if holder != os.Getpid() || !alive {
		t.Errorf("接管后持有者应为当前进程, got holder=%d alive=%v", holder, alive)
	}
}

func TestAcquireTunnelLock_SameProcessTwice(t *testing.T) {
	useTempStateDir(t)

	// 同一进程重复占用同一隧道（如控制通道重复启动）视为已持有，不报错。
	lock1, err := AcquireTunnelLock("delta")
	if err != nil {
		t.Fatalf("首次占用失败: %v", err)
	}
	defer lock1.Release()
	lock2, err := AcquireTunnelLock("delta")
	if err != nil {
		t.Fatalf("同进程重复占用应成功: %v", err)
	}
	lock2.Release()
}

func TestLockFileName_Sanitized(t *testing.T) {
	a := lockFileName("a/b:c*d")
	b := lockFileName("a/b:c*d")
	if a != b {
		t.Errorf("同名应生成同名锁文件: %s != %s", a, b)
	}
	if a == lockFileName("a-b_c*d") {
		t.Error("不同隧道名不应生成相同锁文件")
	}
}
