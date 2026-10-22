// Package config 负责基础配置文件的加载与校验。
//
// 自多隧道改造起，配置文件（setting.conf）只承载「基础配置」：
//   - [app]       DB 文件路径
//   - [tun2socks] tun2socks 二进制路径
//   - [log]       日志级别/文件
//
// 隧道（SSH/TUN）、路由与端口转发配置改为持久化在 SQLite（见 internal/store）。
// 本包的 SSH/Tun/Forwards 字段是「运行时聚合模型」：由 store 从 DB 载入单条隧道后
// 填充，供 sshclient / routing / forwarder / tun2socks 复用，不再从配置文件读取。
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/ini.v1"

	"github.com/Omoinemie/sshtun/internal/secret"
)

// Config 是基础配置与运行时单隧道配置的聚合。
type Config struct {
	App       AppConfig
	Web       WebConfig
	Tun2socks Tun2socksConfig
	Log       LogConfig

	// Path 是配置文件本身的路径。
	Path string

	// 以下为运行时字段：由 store 从 DB 载入单条隧道后填充。
	SSH      SSHConfig
	Tun      TunConfig
	Forwards ForwardConfig
}

// AppConfig 是基础配置 [app] 段。
type AppConfig struct {
	// DB 是 SQLite 数据库文件路径；为空时取默认值（~/.sshtun/sshtun.db）。
	DB string
}

// WebConfig 是内置 Web 管理服务 [web] 段。
// 供 `sshtun web`（及 Windows 独立 sshtun-gui）使用；命令行参数可覆盖此处的值。
type WebConfig struct {
	// Hostname 是监听地址，默认 127.0.0.1，可设为 0.0.0.0 对外提供。
	Hostname string
	// Port 是监听端口，默认 8080；为 0 时由内核自动分配。
	Port int
	// CORS 是允许的跨域源列表（逗号分隔），"*" 表示允许任意源；为空表示不启用 CORS。
	CORS string
	// Username 是登录用户名，默认 admin。
	Username string
	// Password 是登录密码；支持明文，或 enc: 前缀的密文（读取时自动解密）。
	// 为空且绑定回环地址时免登录。
	Password string
	// Language 是界面语言：zh | en；为空或 auto 表示按客户端系统语言自动选择。
	Language string
	// Theme 是界面主题：light | dark；为空或 auto 表示按客户端系统主题自动选择。
	Theme string
}

type SSHConfig struct {
	Host          string
	Port          int
	User          string
	Auth          string // password | key
	Password      string
	KeyFile       string
	KeyPassphrase string
	HostKey       string // none | accept-new | strict/ask | known_hosts 文件路径（解析后为路径）
	// HostKeyMode 是解析后的校验模式：none | accept-new | strict。
	// HostKey 仍是展示/持久化用的原始值，HostKeyMode + 解析后的路径供 sshclient 使用。
	HostKeyMode string
	Keepalive   int // 秒
	// ConnectTimeout 建立连接与认证的超时秒数。
	ConnectTimeout int
}

type TunConfig struct {
	Enabled bool
	Name    string
	Address string
	MTU     int
	// Routes 需要走隧道的网段或单 IP（单 IP 归一化为 /32）。
	Routes []string
	// Bypass 强制直连的网段（经原网关）。
	Bypass []string
}

type ForwardConfig struct {
	// Local 每项格式: [bind_addr:]bind_port:target_host:target_port
	Local []ForwardRule
	// Remote 每项格式: [bind_addr:]bind_port:target_host:target_port
	// 远程侧 bind_addr 仅支持端口或 [host:]port 的端口部分。
	Remote []ForwardRule
}

// ForwardRule 是一条端口转发规则。
type ForwardRule struct {
	BindAddr string // 本地(-L)/远端(-R) 监听地址
	BindPort int
	Target   string // host:port
	// Raw 保留原始配置串，便于展示。
	Raw string
}

type Tun2socksConfig struct {
	Path string
}

type LogConfig struct {
	Level string
	// Dir 是日志目录；不为空时日志按日期分割写入 <Dir>/sshtun-YYYY-MM-DD.log。
	Dir string
	// Console 控制日志是否同时输出到控制台：
	//   - ""（默认，auto）：前台运行输出到控制台，后台守护子进程仅写文件；
	//   - "true"/"on"：始终输出到控制台；
	//   - "false"/"off"：仅写文件。
	Console string
}

// Defaults
const (
	DefaultSSHPort      = 22
	DefaultTunName      = "sshtun0"
	DefaultTunAddress   = "198.18.0.1/30"
	DefaultTunMTU       = 1500
	DefaultLogLevel     = "info"
	DefaultKeepalive    = 30
	DefaultConnTimeout  = 15
	DefaultTun2socksBin = "tun2socks"
	// DefaultDBFileName 是数据库默认文件名。
	DefaultDBFileName = "sshtun.db"

	// Web 管理服务的默认值。
	DefaultWebHostname = "127.0.0.1"
	DefaultWebPort     = 8080
	DefaultWebUsername = "admin"
)

// DefaultDBPath 返回默认数据库路径：当前工作目录下 config/ 目录中的 sshtun.db
// （即 ./config/sshtun.db），与自动生成的默认配置 [app] db 一致。
func DefaultDBPath() string {
	_ = os.MkdirAll(DefaultConfigDir, 0o700)
	return filepath.Join(DefaultConfigDir, DefaultDBFileName)
}

// DefaultConfigDir 与 DefaultConfigPath 约定首次运行时自动生成配置的位置：
// 当前工作目录下的 config/ 目录。
const (
	DefaultConfigDir  = "config"
	DefaultConfigFile = "setting.conf"
)

// DefaultConfigPath 返回默认配置文件路径：./config/setting.conf。
func DefaultConfigPath() string {
	return filepath.Join(DefaultConfigDir, DefaultConfigFile)
}

// defaultConfigTemplate 是首次运行时自动生成的默认配置内容。
const defaultConfigTemplate = `[app]
db = config/sshtun.db

[web]
hostname = 127.0.0.1
port = 8080
cors =
username = admin
password =

[tun2socks]
path =

[ssh]
connect_timeout = 15
keepalive = 30

[log]
level = info
dir = log
console = auto
`

// ensureDefaultFile 在配置文件不存在时按默认模板生成（含父目录）。
// 配置可能包含 Web 登录密码，权限收紧为仅当前用户可读写。
func ensureDefaultFile(path string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(defaultConfigTemplate), 0o600)
}

// Save 写回配置文件：保留原文件中的注释与未知段，仅更新本包管理的键。
// 文件不存在时按默认模板新建。写入采用「临时文件 + 重命名」，避免中途失败损坏配置。
func Save(path string, c *Config) error {
	if path == "" {
		return fmt.Errorf("config file path is empty")
	}
	var f *ini.File
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		f, err = ini.LoadSources(ini.LoadOptions{
			AllowShadows:            true,
			SkipUnrecognizableLines: false,
			IgnoreInlineComment:     false,
		}, data)
		if err != nil {
			return fmt.Errorf("failed to parse INI: %w", err)
		}
	case os.IsNotExist(err):
		f = ini.Empty()
	default:
		return fmt.Errorf("failed to read the config file: %w", err)
	}

	set := func(section, key, value string) {
		sec, err := f.GetSection(section)
		if err != nil {
			sec, _ = f.NewSection(section)
		}
		sec.Key(key).SetValue(value)
	}
	set("app", "db", c.App.DB)
	set("web", "hostname", c.Web.Hostname)
	set("web", "port", strconv.Itoa(c.Web.Port))
	set("web", "cors", c.Web.CORS)
	set("web", "username", c.Web.Username)
	set("web", "password", c.Web.Password)
	set("web", "language", c.Web.Language)
	set("web", "theme", c.Web.Theme)
	set("tun2socks", "path", c.Tun2socks.Path)
	set("ssh", "connect_timeout", strconv.Itoa(c.SSH.ConnectTimeout))
	set("ssh", "keepalive", strconv.Itoa(c.SSH.Keepalive))
	set("log", "level", c.Log.Level)
	set("log", "dir", c.Log.Dir)
	set("log", "console", c.Log.Console)

	// 原子替换：先写临时文件再重命名，失败时原配置保持不变。
	tmp := path + ".tmp"
	if err := f.SaveTo(tmp); err != nil {
		return fmt.Errorf("failed to write the config file: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("failed to replace the config file: %w", err)
	}
	return nil
}

// Load 读取并解析基础配置，填充默认值后做校验。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read the config file: %w", err)
		}
		// 首次运行：自动生成默认配置文件。
		if werr := ensureDefaultFile(path); werr != nil {
			return nil, fmt.Errorf("failed to generate the default config file: %w", werr)
		}
		if data, err = os.ReadFile(path); err != nil {
			return nil, fmt.Errorf("failed to read the config file: %w", err)
		}
	}
	// 旧版本的配置文件可能是 0644；其中可能含 Web 密码，统一收紧。
	_ = os.Chmod(path, 0o600)
	f, err := ini.LoadSources(ini.LoadOptions{
		AllowShadows:              true,
		SkipUnrecognizableLines:   false,
		IgnoreInlineComment:       false,
		UnescapeValueDoubleQuotes: true,
	}, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse INI: %w", err)
	}

	cfg := &Config{Path: path}
	cfg.applyBaseDefaults()

	if sec, err := f.GetSection("app"); err == nil {
		if db := strings.TrimSpace(sec.Key("db").String()); db != "" {
			// 相对路径基于当前工作目录解析（默认值 config/sshtun.db 即 ./config/sshtun.db）。
			cfg.App.DB = filepath.Clean(db)
		}
	}
	if sec, err := f.GetSection("tun2socks"); err == nil {
		cfg.Tun2socks.Path = strings.TrimSpace(sec.Key("path").String())
	}
	// [ssh] 段为「隧道统一参数」：对所有隧道生效的默认值。
	if sec, err := f.GetSection("ssh"); err == nil {
		if v := strings.TrimSpace(sec.Key("connect_timeout").String()); v != "" {
			if n, cerr := strconv.Atoi(v); cerr == nil {
				cfg.SSH.ConnectTimeout = n
			}
		}
		if v := strings.TrimSpace(sec.Key("keepalive").String()); v != "" {
			if n, cerr := strconv.Atoi(v); cerr == nil {
				cfg.SSH.Keepalive = n
			}
		}
	}
	if sec, err := f.GetSection("log"); err == nil {
		cfg.Log.Level = strings.TrimSpace(sec.Key("level").String())
		cfg.Log.Dir = strings.TrimSpace(sec.Key("dir").String())
		cfg.Log.Console = strings.TrimSpace(sec.Key("console").String())
	}
	// [web] 段：内置 Web 管理服务的监听与鉴权配置。
	if sec, err := f.GetSection("web"); err == nil {
		if v := strings.TrimSpace(sec.Key("hostname").String()); v != "" {
			cfg.Web.Hostname = v
		}
		if v := strings.TrimSpace(sec.Key("port").String()); v != "" {
			n, cerr := strconv.Atoi(v)
			if cerr != nil {
				return nil, fmt.Errorf("[web] invalid port: %q", v)
			}
			cfg.Web.Port = n
		}
		cfg.Web.CORS = strings.TrimSpace(sec.Key("cors").String())
		if v := strings.TrimSpace(sec.Key("username").String()); v != "" {
			cfg.Web.Username = v
		}
		cfg.Web.Password = strings.TrimSpace(sec.Key("password").String())
		cfg.Web.Language = strings.TrimSpace(sec.Key("language").String())
		cfg.Web.Theme = strings.TrimSpace(sec.Key("theme").String())
	}
	// Web 密码支持明文或 enc: 密文；密文需在本机解密（换机器会失败，需重设）。
	if cfg.Web.Password != "" && secret.IsEncrypted(cfg.Web.Password) {
		plain, derr := secret.Decrypt(cfg.Web.Password)
		if derr != nil {
			return nil, fmt.Errorf("[web] failed to decrypt the password: %w", derr)
		}
		cfg.Web.Password = plain
	}

	// 旧格式提示：隧道/转发配置已迁移到 DB。
	for _, legacy := range []string{"tun", "forward"} {
		if f.HasSection(legacy) {
			return nil, fmt.Errorf("the [%s] section in the config file is no longer used: use the `sshtun db tunnel/route/forward` commands to store tunnel, route and port forward settings in the database", legacy)
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyBaseDefaults() {
	c.App.DB = DefaultDBPath()
	c.Log.Level = DefaultLogLevel
	// 隧道统一参数的默认值（可被 [ssh] 段覆盖）。
	c.SSH.Keepalive = DefaultKeepalive
	c.SSH.ConnectTimeout = DefaultConnTimeout
	// Web 管理服务默认值（可被 [web] 段覆盖）。
	c.Web.Hostname = DefaultWebHostname
	c.Web.Port = DefaultWebPort
	c.Web.Username = DefaultWebUsername
}

// ApplyTunnelDefaults 为运行时单隧道配置填充缺省值（由 store 载入后调用）。
func (c *Config) ApplyTunnelDefaults() {
	if c.SSH.Port == 0 {
		c.SSH.Port = DefaultSSHPort
	}
	if c.SSH.User == "" {
		c.SSH.User = "root"
	}
	if c.SSH.Auth == "" {
		c.SSH.Auth = "key"
	}
	if c.SSH.Keepalive == 0 {
		c.SSH.Keepalive = DefaultKeepalive
	}
	if c.SSH.ConnectTimeout == 0 {
		c.SSH.ConnectTimeout = DefaultConnTimeout
	}
	if c.SSH.HostKey == "" {
		c.SSH.HostKey = "accept-new"
	}
	if c.Tun.Name == "" {
		c.Tun.Name = DefaultTunName
	}
	if c.Tun.Address == "" {
		c.Tun.Address = DefaultTunAddress
	}
	if c.Tun.MTU == 0 {
		c.Tun.MTU = DefaultTunMTU
	}
}

// ResolveSSHPaths 解析 SSH 相关的相对路径（基于配置文件所在目录）：
//   - key_file 相对路径 → <配置目录>/key_file
//   - host_key: none 不校验；accept-new 首次自动信任；strict/ask 必须已信任；
//     其余视为 known_hosts 文件路径。同时写入 HostKeyMode 供 sshclient 使用。
func (c *Config) ResolveSSHPaths() {
	if c.SSH.KeyFile != "" && !filepath.IsAbs(c.SSH.KeyFile) {
		c.SSH.KeyFile = filepath.Join(filepath.Dir(c.Path), c.SSH.KeyFile)
	}
	raw := strings.TrimSpace(c.SSH.HostKey)
	switch raw {
	case "", "none":
		c.SSH.HostKey = "none"
		c.SSH.HostKeyMode = "none"
		return
	case "accept-new":
		c.SSH.HostKeyMode = "accept-new"
	case "ask", "strict":
		c.SSH.HostKeyMode = "strict"
	default:
		c.SSH.HostKeyMode = "strict"
		if !filepath.IsAbs(raw) {
			c.SSH.HostKey = filepath.Join(filepath.Dir(c.Path), raw)
		}
		return
	}
	// 模式值统一映射到配置目录下的 known_hosts 文件。
	c.SSH.HostKey = filepath.Join(filepath.Dir(c.Path), "known_hosts")
}

// HostKeyStrict 报告是否需要对主机密钥进行信任校验（host_key != none）。
func (c *Config) HostKeyStrict() bool {
	if c.SSH.HostKeyMode != "" {
		return c.SSH.HostKeyMode != "none"
	}
	return c.SSH.HostKey != "" && c.SSH.HostKey != "none"
}

// Validate 校验基础配置。
func (c *Config) Validate() error {
	if c.Log.Level == "" {
		c.Log.Level = DefaultLogLevel
	}
	if c.App.DB == "" {
		c.App.DB = DefaultDBPath()
	}
	if c.Web.Hostname == "" {
		c.Web.Hostname = DefaultWebHostname
	}
	if c.Web.Username == "" {
		c.Web.Username = DefaultWebUsername
	}
	if c.Web.Port < 0 || c.Web.Port > 65535 {
		return fmt.Errorf("[web] invalid port: %d", c.Web.Port)
	}
	// language / theme 为空表示自动（按客户端系统语言/主题选择），故允许空值。
	switch c.Web.Language {
	case "", "auto", "zh", "en":
	default:
		return fmt.Errorf("[web] invalid language: %q (expected auto, zh or en)", c.Web.Language)
	}
	switch c.Web.Theme {
	case "", "auto", "light", "dark":
	default:
		return fmt.Errorf("[web] invalid theme: %q (expected auto, light or dark)", c.Web.Theme)
	}
	return nil
}

// ValidateTunnel 校验单条隧道配置（SSH + TUN + 转发）。
func (c *Config) ValidateTunnel() error {
	if c.SSH.Host == "" {
		return fmt.Errorf("[ssh] host must not be empty")
	}
	if c.SSH.Port < 1 || c.SSH.Port > 65535 {
		return fmt.Errorf("[ssh] invalid port: %d", c.SSH.Port)
	}
	if c.SSH.Auth != "password" && c.SSH.Auth != "key" {
		return fmt.Errorf("[ssh] auth only supports password / key, current: %q", c.SSH.Auth)
	}
	// password 允许为空：表示尚未设置，连接时会前台提示输入并加密回写。
	if c.SSH.Auth == "key" && c.SSH.KeyFile == "" {
		return fmt.Errorf("[ssh] auth=key but key_file is not configured")
	}
	if c.SSH.Keepalive < 0 {
		return fmt.Errorf("[ssh] keepalive must not be negative")
	}
	if c.SSH.ConnectTimeout <= 0 {
		c.SSH.ConnectTimeout = DefaultConnTimeout
	}
	if c.Tun.Enabled {
		if c.Tun.Name == "" {
			return fmt.Errorf("[tun] name must not be empty")
		}
		if _, _, err := net.ParseCIDR(c.Tun.Address); err != nil {
			return fmt.Errorf("[tun] invalid address CIDR %q: %w", c.Tun.Address, err)
		}
		if c.Tun.MTU < 576 || c.Tun.MTU > 65535 {
			return fmt.Errorf("[tun] invalid mtu: %d", c.Tun.MTU)
		}
		for i, r := range c.Tun.Routes {
			if err := validateCIDROrIP(r); err != nil {
				return fmt.Errorf("[tun] routes[%d] %q: %w", i, r, err)
			}
		}
		for i, r := range c.Tun.Bypass {
			if err := validateCIDROrIP(r); err != nil {
				return fmt.Errorf("[tun] bypass[%d] %q: %w", i, r, err)
			}
		}
	}
	return nil
}

func validateCIDROrIP(s string) error {
	if strings.Contains(s, "/") {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return fmt.Errorf("invalid CIDR: %w", err)
		}
		return nil
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("invalid IP address")
	}
	return nil
}

// NormalizeRoutes 将单 IP 归一化为 /32，把 0.0.0.0/0 展开为 0.0.0.0/1 + 128.0.0.0/1。
func (c *Config) NormalizeRoutes() []string {
	var out []string
	for _, r := range c.Tun.Routes {
		if !strings.Contains(r, "/") {
			r = r + "/32"
		}
		if r == "0.0.0.0/0" || r == "::/0" {
			out = append(out, "0.0.0.0/1", "128.0.0.0/1")
			continue
		}
		out = append(out, r)
	}
	return out
}

// NormalizeBypass 与 NormalizeRoutes 同规则处理 bypass 列表。
func (c *Config) NormalizeBypass() []string {
	var out []string
	for _, r := range c.Tun.Bypass {
		if !strings.Contains(r, "/") {
			r = r + "/32"
		}
		out = append(out, r)
	}
	return out
}

// SSHEndpoint 返回 host:port。
func (c *Config) SSHEndpoint() string {
	return net.JoinHostPort(c.SSH.Host, strconv.Itoa(c.SSH.Port))
}
