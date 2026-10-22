package cmd

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/term"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/secret"
	"github.com/Omoinemie/sshtun/internal/sshclient"
	"github.com/Omoinemie/sshtun/internal/sshtest"
)

// memSaver 记录认证重试时更新的凭据，替代数据库持久化。
type memSaver struct {
	user string
	pass string
}

func (m *memSaver) SaveUser(user string) error    { m.user = user; return nil }
func (m *memSaver) SavePassword(enc string) error { m.pass = enc; return nil }

// tamperCiphertext 改动密文中部的一个字符（必影响解码后的字节，
// 避免只改到 base64 末尾填充位而实际未变），使其无法解密。
func tamperCiphertext(enc string) string {
	i := len(enc) / 2
	c := "A"
	if enc[i:i+1] == "A" {
		c = "B"
	}
	return enc[:i] + c + enc[i+1:]
}

// encFor 返回明文对应的加密存储值。
func encFor(t *testing.T, plain string) string {
	t.Helper()
	enc, err := secret.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// 配置中已是加密值时应直接解密使用，不提示输入。
func TestResolvePasswordUsesEncryptedValue(t *testing.T) {
	cfg := &config.Config{}
	cfg.SSH = config.SSHConfig{Auth: "password", Password: encFor(t, "p@ssw0rd")}

	prompted := false
	prompt := func() (string, error) { prompted = true; return "other", nil }
	if _, err := resolvePassword(cfg, prompt); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if prompted {
		t.Fatal("加密密码可用时不应提示输入")
	}
	if cfg.SSH.Password != "p@ssw0rd" {
		t.Fatalf("应使用解密后的密码，实际 %q", cfg.SSH.Password)
	}
}

// 明文密码应被忽略、改为提示输入新密码。
func TestResolvePasswordIgnoresPlaintext(t *testing.T) {
	cfg := &config.Config{}
	cfg.SSH = config.SSHConfig{Auth: "password", Password: "plain-old-pw"}

	if _, err := resolvePassword(cfg, func() (string, error) { return "new-secret", nil }); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if cfg.SSH.Password != "new-secret" {
		t.Fatalf("应使用新输入的密码，实际 %q", cfg.SSH.Password)
	}
}

// 新输入的密码应加密后写入 saver，且二次使用可免输入解密。
func TestPersistPasswordEncryptsToSaver(t *testing.T) {
	saver := &memSaver{}
	if err := persistPassword(saver, "new-secret"); err != nil {
		t.Fatalf("持久化失败: %v", err)
	}
	if !secret.IsEncrypted(saver.pass) {
		t.Fatalf("saver 中应为密文: %q", saver.pass)
	}
	if strings.Contains(saver.pass, "new-secret") {
		t.Fatalf("saver 中不应残留明文: %q", saver.pass)
	}

	// 二次使用：以保存的密文构造配置后可直接解密，无需再输入。
	cfg := &config.Config{}
	cfg.SSH = config.SSHConfig{Auth: "password", Password: saver.pass}
	if _, err := resolvePassword(cfg, nil); err != nil {
		t.Fatalf("无提示器时也应能解密: %v", err)
	}
	if cfg.SSH.Password != "new-secret" {
		t.Fatalf("解密结果错误: %q", cfg.SSH.Password)
	}
}

// 空密码值同样应触发提示输入。
func TestResolvePasswordEmptyTriggersPrompt(t *testing.T) {
	cfg := &config.Config{}
	cfg.SSH = config.SSHConfig{Auth: "password", Password: ""}

	prompted := false
	if _, err := resolvePassword(cfg, func() (string, error) { prompted = true; return "typed", nil }); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !prompted {
		t.Fatal("空密码应触发提示输入")
	}
}

// 不可交互且无可用加密密码时必须失败。
func TestResolvePasswordUnavailableWithoutPrompt(t *testing.T) {
	cfg := &config.Config{}
	cfg.SSH = config.SSHConfig{Auth: "password", Password: "plaintext"}
	if _, err := resolvePassword(cfg, nil); err == nil {
		t.Fatal("不可交互时应报错")
	}
}

// 密文无法解密（如换了一版二进制/被篡改）时应重新提示输入。
func TestResolvePasswordFallsBackWhenDecryptFails(t *testing.T) {
	tampered := tamperCiphertext(encFor(t, "on-machine-a"))
	cfg := &config.Config{}
	cfg.SSH = config.SSHConfig{Auth: "password", Password: tampered}

	prompted := false
	if _, err := resolvePassword(cfg, func() (string, error) { prompted = true; return "retyped", nil }); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !prompted {
		t.Fatal("解密失败时应提示输入")
	}
	if cfg.SSH.Password != "retyped" {
		t.Fatalf("应使用新输入密码，实际 %q", cfg.SSH.Password)
	}
}

// 认证被拒（密码不符）时应提示重输并以新密码重试，成功后加密写入 saver。
func TestConnectWithPasswordRetriesOnAuthFailure(t *testing.T) {
	srv := sshtest.Start(t)
	cfg := testServerConfig(t, srv, "none")
	cfg.SSH.Password = encFor(t, "stale-password")

	saver := &memSaver{}
	prompts := 0
	cli := sshclient.New(cfg)
	if err := connectWithPrompts(cfg, cli, authPrompts{pass: func() (string, error) { prompts++; return "test", nil }}, saver); err != nil {
		t.Fatalf("认证失败后应能用新密码重试成功: %v", err)
	}
	_ = cli.Close()
	if prompts != 1 {
		t.Fatalf("应恰好提示一次，实际 %d 次", prompts)
	}
	if !secret.IsEncrypted(saver.pass) {
		t.Fatalf("新密码应加密保存: %q", saver.pass)
	}
	if plain, err := secret.Decrypt(saver.pass); err != nil || plain != "test" {
		t.Fatalf("保存的密码解密错误: %q, %v", plain, err)
	}
}

// 网络层失败（连不上）不应提示输入密码。
func TestConnectWithPasswordNoPromptOnNetworkFailure(t *testing.T) {
	cfg := &config.Config{}
	cfg.SSH = config.SSHConfig{
		Host: "127.0.0.1", Port: 1, User: "test",
		Auth: "password", Password: encFor(t, "whatever"),
		HostKey: "none", ConnectTimeout: 2,
	}

	prompts := 0
	err := connectWithPrompts(cfg, sshclient.New(cfg), authPrompts{pass: func() (string, error) { prompts++; return "x", nil }}, nil)
	if err == nil {
		t.Fatal("应连接失败")
	}
	if sshclient.IsAuthError(err) {
		t.Fatalf("连不上不应被判为认证错误: %v", err)
	}
	if prompts != 0 {
		t.Fatalf("网络层失败不应提示密码，实际提示 %d 次", prompts)
	}
}

// 密码正确时不应提示。
func TestConnectWithPasswordNoPromptOnSuccess(t *testing.T) {
	srv := sshtest.Start(t)
	cfg := testServerConfig(t, srv, "none")

	prompts := 0
	cli := sshclient.New(cfg)
	if err := connectWithPrompts(cfg, cli, authPrompts{pass: func() (string, error) { prompts++; return "x", nil }}, nil); err != nil {
		t.Fatalf("应连接成功: %v", err)
	}
	_ = cli.Close()
	if prompts != 0 {
		t.Fatalf("认证成功不应提示密码，实际提示 %d 次", prompts)
	}
}

// 密码错、用户名对：用户名直接回车保持不变，只重输密码。
func TestConnectWithPromptsKeepsUserOnEmpty(t *testing.T) {
	srv := sshtest.Start(t)
	cfg := testServerConfig(t, srv, "none")
	cfg.SSH.Password = encFor(t, "stale-password")

	saver := &memSaver{}
	askedUser := false
	prompts := authPrompts{
		user: func(current string) (string, error) {
			askedUser = true
			if current != "test" {
				t.Errorf("提示用户名时应带上当前值，实际 %q", current)
			}
			return "", nil // 回车保持
		},
		pass: func() (string, error) { return "test", nil },
	}
	cli := sshclient.New(cfg)
	if err := connectWithPrompts(cfg, cli, prompts, saver); err != nil {
		t.Fatalf("用户名保持、只重输密码后应连接成功: %v", err)
	}
	_ = cli.Close()
	if !askedUser {
		t.Fatal("认证失败时应提示用户名（可回车保持）")
	}
	if cfg.SSH.User != "test" {
		t.Fatalf("回车保持后用户名不应变化，实际 %q", cfg.SSH.User)
	}
	if saver.user != "" {
		t.Fatalf("回车保持时不应写入用户名，实际 %q", saver.user)
	}
	if plain, err := secret.Decrypt(saver.pass); err != nil || plain != "test" {
		t.Fatalf("保存的密码解密结果错误: %q, %v", plain, err)
	}
}

// 用户名与密码都错：可同时更正两者并写入 saver。
func TestConnectWithPromptsFixesUserAndPassword(t *testing.T) {
	srv := sshtest.Start(t)
	cfg := testServerConfig(t, srv, "none")
	cfg.SSH.User = "bob"
	cfg.SSH.Password = encFor(t, "stale-password")

	saver := &memSaver{}
	prompts := authPrompts{
		user: func(current string) (string, error) {
			if current != "bob" {
				t.Errorf("应提示当前用户名，实际 %q", current)
			}
			return "test", nil
		},
		pass: func() (string, error) { return "test", nil },
	}
	cli := sshclient.New(cfg)
	if err := connectWithPrompts(cfg, cli, prompts, saver); err != nil {
		t.Fatalf("更正用户名与密码后应连接成功: %v", err)
	}
	_ = cli.Close()

	if cfg.SSH.User != "test" || saver.user != "test" {
		t.Fatalf("用户名应已回写: cfg=%q saver=%q", cfg.SSH.User, saver.user)
	}
	if plain, err := secret.Decrypt(saver.pass); err != nil || plain != "test" {
		t.Fatalf("密码应已回写，解密结果错误: %q, %v", plain, err)
	}
}

// key 认证下用户名写错：同样提示更正用户名（且不涉及密码）。
func TestConnectWithPromptsKeyAuthFixesUser(t *testing.T) {
	srv := sshtest.Start(t)
	keyPath := srv.WriteClientKey(t, filepath.Join(t.TempDir(), "id_ed25519"))
	host, portStr, _ := net.SplitHostPort(srv.Addr)
	port, _ := strconv.Atoi(portStr)

	cfg := &config.Config{}
	cfg.SSH = config.SSHConfig{
		Host: host, Port: port, User: "bob", Auth: "key",
		KeyFile: keyPath, HostKey: "none",
		Keepalive: config.DefaultKeepalive, ConnectTimeout: config.DefaultConnTimeout,
	}

	saver := &memSaver{}
	// pass 为 nil：key 认证不应提示密码
	prompts := authPrompts{user: func(string) (string, error) { return "test", nil }}
	cli := sshclient.New(cfg)
	if err := connectWithPrompts(cfg, cli, prompts, saver); err != nil {
		t.Fatalf("更正用户名后 key 认证应成功: %v", err)
	}
	_ = cli.Close()
	if saver.user != "test" {
		t.Fatalf("用户名应已回写，实际 %q", saver.user)
	}
}

// 不可交互（后台子进程）时认证失败应直接报错，不挂起。
func TestConnectWithPasswordNoPromptInBackground(t *testing.T) {
	t.Setenv(daemonEnv, "1")
	srv := sshtest.Start(t)
	cfg := testServerConfig(t, srv, "none")
	cfg.SSH.Password = encFor(t, "wrong-password")

	err := connectWithPassword(cfg, sshclient.New(cfg), nil)
	if err == nil {
		t.Fatal("密码错误时应报错")
	}
	if !sshclient.IsAuthError(err) {
		t.Fatalf("应为认证错误: %v", err)
	}
	if !strings.Contains(err.Error(), "in the foreground to check the user/password") {
		t.Fatalf("应提示前台重跑: %v", err)
	}
}

// 端到端（需真实终端）：认证被拒时从终端读取用户名与密码、加密写入 saver 并重试成功。
// 普通 `go test`（无 TTY）会跳过。实测（go test 不会把 TTY 透给测试二进制，需先编译）：
//
//	go test -c -o /tmp/cmd.test ./cmd
//	printf 'test\ntest\n' | script -qec "/tmp/cmd.test -test.run TTY -test.v" /dev/null
//
// 第一行为用户名（服务端要求 test），第二行为密码。
func TestConnectWithPasswordInteractiveRetryTTY(t *testing.T) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("需要交互终端：请用 script 或真实终端运行")
	}
	t.Setenv(daemonEnv, "")
	srv := sshtest.Start(t)
	cfg := testServerConfig(t, srv, "none")
	cfg.SSH.User = "bob" // 用户名与密码都错：这次要同时更正
	cfg.SSH.Password = encFor(t, "stale-password")

	saver := &memSaver{}
	cli := sshclient.New(cfg)
	if err := connectWithPassword(cfg, cli, saver); err != nil {
		t.Fatalf("应在终端输入正确用户名与密码后连接成功: %v", err)
	}
	_ = cli.Close()

	if cfg.SSH.User != "test" || saver.user != "test" {
		t.Fatalf("应写入终端输入的用户名: cfg=%q saver=%q", cfg.SSH.User, saver.user)
	}
	if plain, err := secret.Decrypt(saver.pass); err != nil || plain != "test" {
		t.Fatalf("应写入终端输入的密码: %q, %v", plain, err)
	}
}

// 端到端：明文密码 -> 交互输入 -> 加密写入 saver -> 用解析出的密码成功建立 SSH 连接。
func TestPreparePasswordEndToEnd(t *testing.T) {
	srv := sshtest.Start(t)
	cfg := testServerConfig(t, srv, "none")
	cfg.SSH.Password = "wrong-plaintext" // 明文应被忽略并提示重输

	saver := &memSaver{}
	if _, err := resolvePassword(cfg, func() (string, error) { return "test", nil }); err != nil {
		t.Fatalf("解析密码失败: %v", err)
	}
	if cfg.SSH.Password != "test" {
		t.Fatalf("应使用输入的密码，实际 %q", cfg.SSH.Password)
	}
	if err := persistPassword(saver, cfg.SSH.Password); err != nil {
		t.Fatalf("持久化失败: %v", err)
	}
	cli := sshclient.New(cfg)
	if err := cli.Connect(); err != nil {
		t.Fatalf("使用解析后的密码连接失败: %v", err)
	}
	_ = cli.Close()

	// 二次使用：密文可直接解密，无需再次输入。
	cfg2 := &config.Config{}
	cfg2.SSH = config.SSHConfig{Auth: "password", Password: saver.pass}
	if _, err := resolvePassword(cfg2, nil); err != nil {
		t.Fatalf("二次使用应免输入: %v", err)
	}
	if cfg2.SSH.Password != "test" {
		t.Fatalf("二次解密结果错误: %q", cfg2.SSH.Password)
	}
}
