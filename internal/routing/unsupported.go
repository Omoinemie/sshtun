//go:build !linux && !windows

// Package routing 的占位实现：仅支持 Linux 与 Windows。
package routing

import (
	"errors"
	"time"

	"github.com/Omoinemie/sshtun/internal/config"
)

// DeviceArg 未支持平台占位。
func DeviceArg(name string) string { return name }

// Setup 未支持平台返回错误。
func Setup(cfg *config.Config, sshHost string) ([]RouteEntry, error) {
	return nil, errors.New("sshtun TUN mode is only supported on Linux and Windows")
}

// Teardown 未支持平台为空操作。
func Teardown(entries []RouteEntry, iface string) {}

// WaitGone 未支持平台占位：直接视为已释放。
func WaitGone(iface string, timeout time.Duration) bool { return true }
