//go:build windows

package cmd

// Windows：用系统默认浏览器打开 URL，不依赖 WebView2。

import (
	"fmt"
	"os/exec"
)

// openBrowserDefault 用系统默认浏览器打开 URL；优先 rundll32，回退 cmd start。
func openBrowserDefault(url string) error {
	if err := exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start(); err == nil {
		return nil
	}
	if err := exec.Command("cmd", "/c", "start", "", url).Start(); err != nil {
		return fmt.Errorf("failed to open the browser: %w", err)
	}
	return nil
}
