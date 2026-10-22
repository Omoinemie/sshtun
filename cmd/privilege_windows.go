//go:build windows

package cmd

import "golang.org/x/sys/windows"

// hasPrivileges 检测是否具备管理员权限。
func hasPrivileges() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
