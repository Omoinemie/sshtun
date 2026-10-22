// Package logging 提供全局 slog 日志：级别与输出目标由配置决定。
package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var logger *slog.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

// Setup 初始化全局日志。
//   - level:   日志级别（debug|info|warn|error），无法识别时按 info 处理；
//   - dir:     日志目录；为空则日志输出 stderr，否则按日期分割写入
//     <dir>/sshtun-YYYY-MM-DD.log（跨天自动切换文件）；
//   - console: 为真时日志同时输出到 stderr（前台运行时的实时日志）。
//
// dir 为空且 console 为假时仍以 stderr 为唯一输出目标，保证任何情况下都有日志落地。
func Setup(level, dir string, console bool) error {
	lvl := slog.LevelInfo
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info", "":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	var targets []io.Writer
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		targets = append(targets, &dateWriter{dir: dir})
	}
	if console {
		targets = append(targets, os.Stderr)
	}
	if len(targets) == 0 {
		targets = append(targets, os.Stderr)
	}
	var w io.Writer = targets[0]
	if len(targets) > 1 {
		w = io.MultiWriter(targets...)
	}
	logger = slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl}))
	return nil
}

// dateWriter 按日期把日志写入 <dir>/sshtun-YYYY-MM-DD.log，跨天自动换文件。
type dateWriter struct {
	mu  sync.Mutex
	dir string
	day string
	f   *os.File
}

func (d *dateWriter) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	today := time.Now().Format("2006-01-02")
	if d.f == nil || d.day != today {
		name := filepath.Join(d.dir, "sshtun-"+today+".log")
		f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return 0, err
		}
		if d.f != nil {
			_ = d.f.Close()
		}
		d.f, d.day = f, today
	}
	return d.f.Write(p)
}

func Debug(msg string, args ...any) { logger.Debug(msg, args...) }
func Info(msg string, args ...any)  { logger.Info(msg, args...) }
func Warn(msg string, args ...any)  { logger.Warn(msg, args...) }
func Error(msg string, args ...any) { logger.Error(msg, args...) }
