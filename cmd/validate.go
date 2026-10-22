package cmd

// 隧道名校验与启动失败分类：CLI 与 Web GUI 共用。
// 隧道名会被当作命令行参数、URL 段与日志字段使用，因此沿用文件名的字符约束
// （禁止空格与 <>:"/\|?* 等非法字符），并排除保留名 all。

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/Omoinemie/sshtun/internal/sshclient"
)

// maxTunnelNameLen 是隧道名的最大字符数（按 rune 计）。
const maxTunnelNameLen = 32

// allTunnelName 是 start/stop/restart/check 中表示「全部隧道」的保留名。
const allTunnelName = "all"

// fileNameBadChars 是 Windows/POSIX 文件名都不允许的字符集合；
// 隧道名复用文件名的字符约束（外加空格），避免落到路径、URL 或命令行时出问题。
const fileNameBadChars = `<>:"/\|?*`

// validateTunnelName 校验隧道名：非空、长度受限、不含空格、不含文件名不允许的
// 字符（控制字符与 <>:"/\|?*，且不能以 . 结尾），且不得使用保留名 all。
// 其余符号（- _ # @ ( ) + % 等）与中英文、数字一律放行。
func validateTunnelName(name string) error {
	n := strings.TrimSpace(name)
	if n == "" {
		return errors.New("the tunnel name must not be empty")
	}
	if len([]rune(n)) > maxTunnelNameLen {
		return fmt.Errorf("the tunnel name is too long (at most %d characters)", maxTunnelNameLen)
	}
	if strings.EqualFold(n, allTunnelName) {
		return fmt.Errorf("the tunnel name must not be the reserved name %q (it means \"all tunnels\")", allTunnelName)
	}
	for _, r := range n {
		switch {
		case unicode.IsSpace(r):
			return fmt.Errorf("the tunnel name must not contain spaces: %q", string(r))
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("the tunnel name must not contain control characters: %q", string(r))
		case strings.ContainsRune(fileNameBadChars, r):
			return fmt.Errorf("the tunnel name must not contain characters that are invalid in file names: %q", string(r))
		}
	}
	// Windows 不允许文件名以点结尾（否则 . 与 .. 等同路径写法会被吞掉）。
	if strings.HasSuffix(n, ".") {
		return errors.New("the tunnel name must not end with a dot")
	}
	return nil
}

// isCredentialError 报告启动失败是否由 SSH 认证凭据引起（用户名、密码或私钥）。
// 这类失败可在界面上重新填写凭据后重试；网络不通、路由冲突等其余失败不能。
func isCredentialError(err error) bool {
	if err == nil {
		return false
	}
	if sshclient.IsAuthError(err) {
		return true
	}
	msg := err.Error()
	for _, kw := range []string{
		"needs an encrypted password", // auth=password but no usable password in the database
		"read the private key",        // the private key file is missing or unreadable
		"parse the private key",       // the private key format or its passphrase is wrong
		"unsupported authentication method",
	} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}
