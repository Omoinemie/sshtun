//go:build linux

package cmd

import "os"

// hasPrivileges 检测是否具备配置 TUN/路由的权限（root）。
func hasPrivileges() bool { return os.Geteuid() == 0 }
