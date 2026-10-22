//go:build !linux && !windows

package cmd

// hasPrivileges 未支持平台返回 false（TUN 模式不可用）。
func hasPrivileges() bool { return false }
