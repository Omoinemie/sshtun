package cmd

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateTunnelName(t *testing.T) {
	// 文件名允许的字符一律放行：中英文、数字与 - _ # @ ( ) + % 等符号。
	ok := []string{
		"office", "家庭网络", "ssh1", "A节点2号", "tunnel01",
		"tunnel-01", "vpn_2号", "线路(主)", "my@node", "a+b#c", "30%线路", "a.b",
	}
	for _, n := range ok {
		if err := validateTunnelName(n); err != nil {
			t.Errorf("validateTunnelName(%q) 应通过，实际: %v", n, err)
		}
	}

	bad := map[string]string{
		"":                      "must not be empty",
		"   ":                   "must not be empty",
		"all":                   "reserved name",
		"ALL":                   "reserved name",
		"All":                   "reserved name",
		"a b":                   "spaces",
		"my tunnel":             "spaces",
		"a\u0007b":              "control characters",
		"<a>":                   "invalid in file names",
		"a:b":                   "invalid in file names",
		`a"b`:                   "invalid in file names",
		"a/b":                   "invalid in file names",
		`a\b`:                   "invalid in file names",
		"a|b":                   "invalid in file names",
		"a?b":                   "invalid in file names",
		"a*b":                   "invalid in file names",
		"abc.":                  "must not end with a dot",
		strings.Repeat("长", 33): "too long",
	}
	for n, want := range bad {
		err := validateTunnelName(n)
		if err == nil {
			t.Errorf("validateTunnelName(%q) 应被拒绝", n)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("validateTunnelName(%q) 错误文案应含 %q，实际: %v", n, want, err)
		}
	}
}

func TestIsCredentialError(t *testing.T) {
	auth := errors.New("SSH handshake/authentication failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain")
	noPwd := errors.New("auth=password needs an encrypted password, and the current session is not interactive; run it in the foreground to enter the password")
	badKey := errors.New("failed to read the private key C:\\id_rsa: the system cannot find the file specified")
	other := errors.New("failed to connect to 1.2.3.4:22: dial tcp: i/o timeout")

	if !isCredentialError(auth) {
		t.Error("对端拒绝认证应识别为凭据类失败")
	}
	if !isCredentialError(noPwd) {
		t.Error("缺少密码应识别为凭据类失败")
	}
	if !isCredentialError(badKey) {
		t.Error("私钥读取失败应识别为凭据类失败")
	}
	if isCredentialError(other) {
		t.Error("网络超时不应当作凭据类失败")
	}
	if isCredentialError(nil) {
		t.Error("nil 不应是凭据类失败")
	}
}
