package hostkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("转换公钥失败: %v", err)
	}
	return key
}

func TestCheckUnknownWhenFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	st, err := Check(path, "203.0.113.10:22", newKey(t))
	if err != nil {
		t.Fatalf("Check 出错: %v", err)
	}
	if st != StatusUnknown {
		t.Fatalf("期望 StatusUnknown，实际 %v", st)
	}
}

func TestAddThenTrusted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "known_hosts")
	key := newKey(t)

	if err := Add(path, "203.0.113.10:22", key); err != nil {
		t.Fatalf("Add 失败: %v", err)
	}
	// 默认端口 22 在 known_hosts 中不带端口
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if !strings.HasPrefix(string(data), "203.0.113.10 ") {
		t.Fatalf("known_hosts 内容不符合预期: %q", string(data))
	}

	st, err := Check(path, "203.0.113.10:22", key)
	if err != nil {
		t.Fatalf("Check 出错: %v", err)
	}
	if st != StatusTrusted {
		t.Fatalf("期望 StatusTrusted，实际 %v", st)
	}
}

func TestNonDefaultPortFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := newKey(t)
	if err := Add(path, "203.0.113.10:2222", key); err != nil {
		t.Fatalf("Add 失败: %v", err)
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), "[203.0.113.10]:2222 ") {
		t.Fatalf("非默认端口应写成 [host]:port，实际: %q", string(data))
	}
	st, err := Check(path, "203.0.113.10:2222", key)
	if err != nil {
		t.Fatalf("Check 出错: %v", err)
	}
	if st != StatusTrusted {
		t.Fatalf("期望 StatusTrusted，实际 %v", st)
	}
}

func TestChangedKeyDetectedAndReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	oldKey := newKey(t)
	newK := newKey(t)

	if err := Add(path, "host.example.com:22", oldKey); err != nil {
		t.Fatalf("Add 失败: %v", err)
	}
	st, err := Check(path, "host.example.com:22", newK)
	if err != nil {
		t.Fatalf("Check 出错: %v", err)
	}
	if st != StatusChanged {
		t.Fatalf("期望 StatusChanged，实际 %v", st)
	}

	// 替换后旧条目应被移除，新密钥受信任
	if err := Add(path, "host.example.com:22", newK); err != nil {
		t.Fatalf("Add 替换失败: %v", err)
	}
	data, _ := os.ReadFile(path)
	if strings.Count(string(data), "host.example.com ") != 1 {
		t.Fatalf("同宿主条目应被替换为一条，实际: %q", string(data))
	}
	st, _ = Check(path, "host.example.com:22", newK)
	if st != StatusTrusted {
		t.Fatalf("替换后期望 StatusTrusted，实际 %v", st)
	}
	if st, _ := Check(path, "host.example.com:22", oldKey); st == StatusTrusted {
		t.Fatal("旧密钥在替换后不应再被信任")
	}
}

func TestAddPreservesOtherLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte("# 注释\nother.example.com ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if err := Add(path, "203.0.113.10:22", newKey(t)); err != nil {
		t.Fatalf("Add 失败: %v", err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "# 注释") || !strings.Contains(string(data), "other.example.com") {
		t.Fatalf("无关条目被破坏: %q", string(data))
	}
}

func TestFingerprintFormat(t *testing.T) {
	fp := Fingerprint(newKey(t))
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("指纹格式错误: %q", fp)
	}
}
