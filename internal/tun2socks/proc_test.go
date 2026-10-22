package tun2socks

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Omoinemie/sshtun/internal/config"
)

// writeStub 写一个可执行的 stub 脚本，模拟 tun2socks。
func writeStub(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub 脚本依赖 /bin/sh，仅在类 Unix 下运行")
	}
	p := filepath.Join(t.TempDir(), "tun2socks")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func stubCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Tun.MTU = 1500
	cfg.Log.Level = "debug"
	return cfg
}

// 传给 tun2socks 的必须是 `--长选项`：单横线的 -mtu 会被 pflag 当作短选项而报错。
func TestStartUsesLongFlags(t *testing.T) {
	bin := writeStub(t, `echo "$@" >&2; exit 2`)
	_, err := Start(stubCfg(), bin, "tun://sshtun0", "socks5://127.0.0.1:1080")
	if err == nil {
		t.Fatal("stub 已退出，Start 应返回错误")
	}
	want := "--device tun://sshtun0 --proxy socks5://127.0.0.1:1080 --mtu 1500 --loglevel debug"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("参数应为 %q，实际错误: %v", want, err)
	}
}

// sshtun 不认识的日志级别不能透传给 tun2socks（会被拒绝），需回退 info。
func TestStartMapsUnknownLoglevel(t *testing.T) {
	bin := writeStub(t, `echo "$@" >&2; exit 2`)
	cfg := stubCfg()
	cfg.Log.Level = "trace"
	_, err := Start(cfg, bin, "tun://sshtun0", "socks5://127.0.0.1:1080")
	if err == nil {
		t.Fatal("stub 已退出，Start 应返回错误")
	}
	if !strings.Contains(err.Error(), "--loglevel info") {
		t.Fatalf("未知级别应回退 info，实际错误: %v", err)
	}
}

// 立即退出时应把子进程最后的输出带进错误信息，便于定位原因。
func TestStartImmediateExitIncludesOutput(t *testing.T) {
	bin := writeStub(t, `echo 'unknown shorthand flag: "m" in -mtu' >&2; exit 2`)
	_, err := Start(stubCfg(), bin, "tun://sshtun0", "socks5://127.0.0.1:1080")
	if err == nil {
		t.Fatal("stub 已退出，Start 应返回错误")
	}
	if !strings.Contains(err.Error(), "exited immediately after startup") ||
		!strings.Contains(err.Error(), "unknown shorthand flag") ||
		!strings.Contains(err.Error(), "exit status 2") {
		t.Fatalf("错误应包含退出状态与原因行，实际: %v", err)
	}
}
