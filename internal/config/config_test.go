package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omoinemie/sshtun/internal/secret"
)

const baseConf = `
[app]
db = config/sshtun.db

[tun2socks]
path =

[ssh]
connect_timeout = 15
keepalive = 30

[log]
level = debug
dir = log
`

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "setting.conf")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadBase(t *testing.T) {
	p := writeTemp(t, baseConf)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	// db 为相对路径时基于当前工作目录解析（默认 config/sshtun.db 即 ./config/sshtun.db）。
	// Load 会做 filepath.Clean，Windows 下分隔符为 \，按当前平台的清洗结果比较。
	if want := filepath.Clean("config/sshtun.db"); cfg.App.DB != want {
		t.Errorf("db 应为 %s, got %s", want, cfg.App.DB)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log level 应为 debug, got %s", cfg.Log.Level)
	}
	if cfg.SSH.ConnectTimeout != 15 || cfg.SSH.Keepalive != 30 {
		t.Errorf("[ssh] 统一参数解析错误: %+v", cfg.SSH)
	}
}

func TestSaveRoundTrip(t *testing.T) {
	// 含注释与未知段的配置：保存后应保留，且已知键被更新。
	p := writeTemp(t, "# 我的配置\n[app]\ndb = config/sshtun.db\n\n[custom]\nfoo = bar\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	cfg.Log.Level = "debug"
	cfg.Log.Dir = "logs"
	cfg.Log.Console = "true"
	cfg.SSH.ConnectTimeout = 22
	cfg.SSH.Keepalive = 45
	cfg.Web.Hostname = "0.0.0.0"
	cfg.Web.Port = 9090
	cfg.Web.Username = "admin2"
	cfg.Tun2socks.Path = "bin/tun2socks"

	if err := Save(p, cfg); err != nil {
		t.Fatalf("Save 失败: %v", err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatalf("保存后 Load 失败: %v", err)
	}
	if got.Log.Level != "debug" || got.Log.Dir != "logs" || got.Log.Console != "true" {
		t.Errorf("日志设置未生效: %+v", got.Log)
	}
	if got.SSH.ConnectTimeout != 22 || got.SSH.Keepalive != 45 {
		t.Errorf("SSH 参数未生效: %+v", got.SSH)
	}
	if got.Web.Port != 9090 || got.Web.Username != "admin2" {
		t.Errorf("Web 设置未生效: %+v", got.Web)
	}
	if got.Tun2socks.Path != "bin/tun2socks" {
		t.Errorf("tun2socks 路径未生效: %q", got.Tun2socks.Path)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "[custom]") || !strings.Contains(string(raw), "foo = bar") {
		t.Errorf("未知段应被保留:\n%s", raw)
	}
	if !strings.Contains(string(raw), "# 我的配置") {
		t.Errorf("注释应被保留:\n%s", raw)
	}
}

func TestLoadDefaultDB(t *testing.T) {
	p := writeTemp(t, "[log]\nlevel = info\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.App.DB == "" {
		t.Errorf("未配置 [app] db 时应回退到默认路径")
	}
	if !strings.HasSuffix(cfg.App.DB, DefaultDBFileName) {
		t.Errorf("默认 db 应以 %s 结尾, got %s", DefaultDBFileName, cfg.App.DB)
	}
}

func TestRejectLegacySections(t *testing.T) {
	for _, sec := range []string{"tun", "forward"} {
		p := writeTemp(t, "["+sec+"]\nhost = 1.2.3.4\n")
		if _, err := Load(p); err == nil {
			t.Errorf("含 [%s] 段时应报错，提示迁移到 DB", sec)
		}
	}
}

func TestValidateTunnel(t *testing.T) {
	base := func() *Config {
		c := &Config{Path: "setting.conf"}
		c.ApplyTunnelDefaults()
		c.Tun.Enabled = true
		return c
	}

	cases := map[string]func(*Config){
		"缺少host": func(c *Config) { c.SSH.Auth = "key"; c.SSH.KeyFile = "/tmp/k" },
		"auth非法": func(c *Config) { c.SSH.Host = "1.2.3.4"; c.SSH.Auth = "foo" },
		"key缺失":  func(c *Config) { c.SSH.Host = "1.2.3.4"; c.SSH.Auth = "key" },
		"网段非法": func(c *Config) {
			c.SSH.Host = "1.2.3.4"
			c.SSH.Auth = "key"
			c.SSH.KeyFile = "/tmp/k"
			c.Tun.Routes = []string{"999.1.1.0/24"}
		},
	}
	for name, mutate := range cases {
		c := base()
		mutate(c)
		if err := c.ValidateTunnel(); err == nil {
			t.Errorf("%s: 应当报错", name)
		}
	}

	ok := base()
	ok.SSH.Host = "203.0.113.10"
	ok.SSH.Auth = "password"
	ok.Tun.Routes = []string{"10.8.0.0/16", "192.168.7.10"}
	if err := ok.ValidateTunnel(); err != nil {
		t.Errorf("合法隧道不应报错: %v", err)
	}
}

func TestApplyTunnelDefaultsAndPaths(t *testing.T) {
	// 配置路径须为当前平台的真绝对路径：Windows 下 "/etc/..." 缺盘符，
	// filepath.IsAbs 为 false，key_file 会被判为相对路径而拼接。
	confDir, err := filepath.Abs(filepath.Join("etc", "sshtun"))
	if err != nil {
		t.Fatalf("Abs 失败: %v", err)
	}
	c := &Config{Path: filepath.Join(confDir, "setting.conf")}
	c.SSH.Host = "1.2.3.4"
	c.SSH.Auth = "key"
	c.SSH.KeyFile = "id_rsa"
	c.SSH.HostKey = "ask"
	c.ApplyTunnelDefaults()
	c.ResolveSSHPaths()

	if c.SSH.Port != DefaultSSHPort {
		t.Errorf("默认 port 应为 %d, got %d", DefaultSSHPort, c.SSH.Port)
	}
	if !filepath.IsAbs(c.SSH.KeyFile) || !strings.HasSuffix(c.SSH.KeyFile, filepath.Join("sshtun", "id_rsa")) {
		t.Errorf("key_file 应基于配置目录解析: %s", c.SSH.KeyFile)
	}
	if !strings.HasSuffix(c.SSH.HostKey, filepath.Join("sshtun", "known_hosts")) {
		t.Errorf("host_key=ask 应映射为 known_hosts: %s", c.SSH.HostKey)
	}
}

func TestLoadWeb(t *testing.T) {
	// 未配置 [web] 时使用默认值。
	p := writeTemp(t, "[app]\ndb = config/sshtun.db\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.Web.Hostname != DefaultWebHostname || cfg.Web.Port != DefaultWebPort || cfg.Web.Username != DefaultWebUsername {
		t.Errorf("web 默认值错误: %+v", cfg.Web)
	}
	if cfg.Web.Password != "" || cfg.Web.CORS != "" {
		t.Errorf("web 默认可选项应为空: %+v", cfg.Web)
	}

	// 显式配置 + 密文密码自动解密。
	enc, eerr := secret.Encrypt("s3cret")
	if eerr != nil {
		t.Fatalf("加密失败: %v", eerr)
	}
	p2 := writeTemp(t, "[web]\nhostname = 0.0.0.0\nport = 18099\n"+
		"cors = https://a.example,https://b.example\nusername = bob\npassword = "+enc+"\n")
	cfg2, err := Load(p2)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg2.Web.Hostname != "0.0.0.0" || cfg2.Web.Port != 18099 {
		t.Errorf("web 监听配置错误: %+v", cfg2.Web)
	}
	if cfg2.Web.Username != "bob" || cfg2.Web.Password != "s3cret" {
		t.Errorf("web 凭据/解密错误: user=%q pass=%q", cfg2.Web.Username, cfg2.Web.Password)
	}
	if cfg2.Web.CORS != "https://a.example,https://b.example" {
		t.Errorf("web cors 解析错误: %q", cfg2.Web.CORS)
	}
}

func TestNormalizeRoutes(t *testing.T) {
	c := &Config{}
	c.Tun.Routes = []string{"0.0.0.0/0", "10.0.0.5", "192.168.0.0/16"}
	got := c.NormalizeRoutes()
	want := []string{"0.0.0.0/1", "128.0.0.0/1", "10.0.0.5/32", "192.168.0.0/16"}
	if len(got) != len(want) {
		t.Fatalf("NormalizeRoutes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("NormalizeRoutes[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}
