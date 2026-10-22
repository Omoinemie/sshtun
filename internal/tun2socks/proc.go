// Package tun2socks 负责查找、启动与停止 tun2socks 子进程。
package tun2socks

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/logging"
)

// Process 是一个 tun2socks 子进程。
type Process struct {
	cmd  *exec.Cmd
	name string

	mu      sync.Mutex
	exited  chan struct{}
	exitErr error

	// recent 保存最近的输出行，用于「启动后立即退出」时把失败原因带进错误信息。
	recent []string

	// drains 用于在子进程立即退出时等待输出读取协程收尾。
	drains sync.WaitGroup
}

// Find 按顺序查找 tun2socks 二进制：
// 配置 path -> 配置目录下的相对 path -> sshtun 可执行文件所在目录 -> 配置目录
// -> ./bin -> 配置目录/bin -> PATH。
// 可执行文件/配置目录优先出现，使「下载打包好的压缩包、解压即运行」无需任何配置。
func Find(cfg *config.Config) (string, error) {
	bin := DefaultBinaryName()
	candidates := []string{}
	if cfg.Tun2socks.Path != "" {
		candidates = append(candidates, cfg.Tun2socks.Path)
	}
	// 相对路径基于配置文件目录
	cfgDir := filepath.Dir(cfg.Path)
	if cfg.Tun2socks.Path != "" && !filepath.IsAbs(cfg.Tun2socks.Path) {
		candidates = append(candidates, filepath.Join(cfgDir, cfg.Tun2socks.Path))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), bin))
	}
	candidates = append(candidates,
		filepath.Join(cfgDir, bin),
		filepath.Join("bin", bin),
		filepath.Join(cfgDir, "bin", bin),
	)
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if info, err := os.Stat(abs); err == nil && !info.IsDir() {
				return abs, nil
			}
		}
	}
	// PATH 查找
	if p, err := exec.LookPath(bin); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("tun2socks binary not found: run `sshtun fetch` to download it, or set the path in the [tun2socks] section of the config file")
}

// DefaultBinaryName 返回当前平台的二进制文件名。
func DefaultBinaryName() string {
	if runtime.GOOS == "windows" {
		return "tun2socks.exe"
	}
	return "tun2socks"
}

// Start 启动 tun2socks 子进程并接管其输出。
// device: Linux 为 tun://<name>，Windows 为 wintun 适配器名。
// proxy:  例如 socks5://127.0.0.1:1080
//
// 选项一律使用 `--长选项` 形式：tun2socks 使用 pflag 解析，
// 单横线的 `-mtu`/`-loglevel` 会被当作短选项（如 -m）而报
// "unknown shorthand flag"，双横线在 v2.x 各版本均有效。
func Start(cfg *config.Config, bin, device, proxy string) (*Process, error) {
	args := []string{
		"--device", device,
		"--proxy", proxy,
		"--mtu", fmt.Sprint(cfg.Tun.MTU),
		"--loglevel", t2sLoglevel(cfg.Log.Level),
	}
	cmd := exec.Command(bin, args...)
	prepareChild(cmd)
	cmd.Stdout = nil
	cmd.Stderr = nil

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tun2socks: %w", err)
	}
	// 把子进程并入父进程的任务对象：sshtun 异常退出时由系统连带结束它，避免残留。
	guardChild(cmd)
	p := &Process{cmd: cmd, name: bin, exited: make(chan struct{})}

	go p.drain(stderr)
	go p.drain(stdout)
	go func() {
		p.exitErr = cmd.Wait()
		close(p.exited)
	}()

	// 短暂等待，若立即退出则报错（如参数不兼容、缺 wintun.dll、权限不足）
	select {
	case <-p.exited:
		p.waitDrains(300 * time.Millisecond)
		if detail := p.recentLines(3); detail != "" {
			return nil, fmt.Errorf("tun2socks exited immediately after startup: %v\n%s", p.exitErr, detail)
		}
		return nil, fmt.Errorf("tun2socks exited immediately after startup: %v", p.exitErr)
	case <-time.After(1500 * time.Millisecond):
	}
	return p, nil
}

// t2sLoglevel 把 sshtun 的日志级别映射为 tun2socks 接受的取值
// (debug|info|warn|error|silent)；无法识别的值回退 info。
func t2sLoglevel(level string) string {
	switch level {
	case "debug", "info", "warn", "error", "silent":
		return level
	default:
		return "info"
	}
}

// Pid 返回子进程 PID。
func (p *Process) Pid() int {
	if p == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// Wait 等待子进程退出。
func (p *Process) Wait() error {
	<-p.exited
	return p.exitErr
}

// Stop 终止子进程（优雅 -> 强制）。
func (p *Process) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.exited:
		return nil
	default:
	}
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	<-p.exited
	return nil
}

// drain 读取子进程的一段输出并记录日志，同时保存最近几行备查。
func (p *Process) drain(r interface{ Read([]byte) (int, error) }) {
	p.drains.Add(1)
	defer p.drains.Done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		logging.Info("tun2socks", "out", line)
		p.mu.Lock()
		p.recent = append(p.recent, line)
		if len(p.recent) > 8 {
			p.recent = p.recent[len(p.recent)-8:]
		}
		p.mu.Unlock()
	}
}

// recentLines 返回最近 n 行输出（每行加缩进，便于拼进错误信息）。
func (p *Process) recentLines(n int) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.recent) == 0 {
		return ""
	}
	start := len(p.recent) - n
	if start < 0 {
		start = 0
	}
	var b strings.Builder
	for _, l := range p.recent[start:] {
		b.WriteString("  tun2socks: " + l + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// waitDrains 在超时内等待输出读取协程收尾（进程退出后管道关闭，通常立刻结束）。
func (p *Process) waitDrains(d time.Duration) {
	done := make(chan struct{})
	go func() {
		p.drains.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
	}
}
