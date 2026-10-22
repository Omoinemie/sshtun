//go:build !windows

package cmd

// 非 Windows：用系统默认浏览器打开 URL（macOS 用 open，其余用 xdg-open）。

import (
	"fmt"
	"os/exec"
	"runtime"
)

// openBrowserDefault 用系统默认浏览器打开 URL。
func openBrowserDefault(url string) error {
	var bin string
	switch runtime.GOOS {
	case "darwin":
		bin = "open"
	default:
		bin = "xdg-open"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return fmt.Errorf("%s not found, cannot open the browser automatically, please visit: %s", bin, url)
	}
	if err := exec.Command(path, url).Start(); err != nil {
		return fmt.Errorf("failed to open the browser: %w", err)
	}
	return nil
}
