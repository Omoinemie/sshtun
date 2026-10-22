// Package daemon 负责运行状态持久化（state/pidfile）、后台化与进程清理。
package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Omoinemie/sshtun/internal/routing"
)

// State 描述一次运行实例的全部可清理资源。
type State struct {
	Pid        int           `json:"pid"`
	Mode       string        `json:"mode"` // tun | forward
	DBPath     string        `json:"db_path,omitempty"`
	ConfigPath string        `json:"config_path"`
	StartedAt  time.Time     `json:"started_at"`
	Tunnels    []TunnelState `json:"tunnels,omitempty"`
}

// TunnelState 是单条隧道的可清理资源。
type TunnelState struct {
	Name string `json:"name"`
	// UID 是隧道稳定标识（改名不变），供界面按 UID 定位运行中的隧道。
	UID          string               `json:"uid,omitempty"`
	Tun2socksPid int                  `json:"tun2socks_pid,omitempty"`
	Iface        string               `json:"iface,omitempty"`
	Listen       string               `json:"listen,omitempty"`
	Routes       []routing.RouteEntry `json:"routes,omitempty"`
	// PeerIP 是 SSH 实际连接到的对端 IP（IPv4 或 IPv6），供界面展示真实连接地址。
	PeerIP string `json:"peer_ip,omitempty"`
	// Up/Down 为该隧道累计上传/下载字节（应用层计数），
	// UpSpeed/DownSpeed 为实时速率（字节/秒）。
	// 均由运行实例采样后周期性刷新，供其它进程（如 Web 界面）展示流量统计。
	Up        int64   `json:"up,omitempty"`
	Down      int64   `json:"down,omitempty"`
	UpSpeed   float64 `json:"up_speed,omitempty"`
	DownSpeed float64 `json:"down_speed,omitempty"`
}

// StateDir 返回状态目录：$HOME/.sshtun（Windows 为 %LOCALAPPDATA%\sshtun）。
func StateDir() (string, error) {
	if runtime.GOOS == "windows" {
		appdata := os.Getenv("LOCALAPPDATA")
		if appdata == "" {
			return "", fmt.Errorf("LOCALAPPDATA is not set")
		}
		dir := filepath.Join(appdata, "sshtun")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".sshtun")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func StateFile() (string, error) {
	dir, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "state.json"), nil
}

// SaveState 原子写入 state.json。
func SaveState(s *State) error {
	path, err := StateFile()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadState 读取 state.json；不存在返回 (nil, nil)。
func LoadState() (*State, error) {
	path, err := StateFile()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("state.json is corrupted: %w", err)
	}
	return &s, nil
}

// ClearState 删除 state.json。
func ClearState() error {
	path, err := StateFile()
	if err != nil {
		return err
	}
	if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
		return rmErr
	}
	return nil
}

// ActiveState 返回处于活跃状态的 State（进程存活）。
func ActiveState() (*State, error) {
	s, err := LoadState()
	if err != nil || s == nil {
		return nil, err
	}
	if !IsAlive(s.Pid) {
		return nil, nil
	}
	return s, nil
}
