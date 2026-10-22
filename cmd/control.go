package cmd

// 控制通道：当实例已运行、且 stop/restart/start 只作用于其中部分隧道时，
// CLI 通过状态目录下的请求/响应文件与常驻主进程通信，由主进程在进程内按名
// 启停或重启单条隧道，其余隧道不受影响。非交互脚本不受影响。

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Omoinemie/sshtun/internal/daemon"
)

// 控制操作类型。
const (
	opStart   = "start"
	opStop    = "stop"
	opRestart = "restart"
)

type controlRequest struct {
	ID    string   `json:"id"`
	Op    string   `json:"op"`
	Names []string `json:"names"`
}

type controlResponse struct {
	OK    bool     `json:"ok"`
	Lines []string `json:"lines,omitempty"`
	Error string   `json:"error,omitempty"`
}

const (
	controlReqName = "control.json"
	controlRespFmt = "control.%s.resp"
)

func controlReqPath() (string, error) {
	dir, err := daemon.StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, controlReqName), nil
}

func controlRespPath(id string) (string, error) {
	dir, err := daemon.StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, fmt.Sprintf(controlRespFmt, id)), nil
}

// writeFileAtomic 先写临时文件再重命名，避免读到半成品。
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// sendControl 向运行中的主进程发送控制请求并等待响应。
func sendControl(op string, names []string) error {
	reqPath, err := controlReqPath()
	if err != nil {
		return err
	}
	id := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	data, err := json.Marshal(controlRequest{ID: id, Op: op, Names: names})
	if err != nil {
		return err
	}
	if err := writeFileAtomic(reqPath, data); err != nil {
		return err
	}

	respPath, err := controlRespPath(id)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		b, rerr := os.ReadFile(respPath)
		if rerr != nil {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		_ = os.Remove(respPath)
		var resp controlResponse
		if err := json.Unmarshal(b, &resp); err != nil {
			return err
		}
		for _, l := range resp.Lines {
			fmt.Println(l)
		}
		if !resp.OK {
			if resp.Error == "" {
				resp.Error = "operation failed"
			}
			return errors.New(resp.Error)
		}
		return nil
	}
	return errors.New("timed out waiting for the main process to answer (is the instance still running?)")
}

// writeControlResponse 由主进程写回控制响应。
func writeControlResponse(id string, resp controlResponse) {
	path, err := controlRespPath(id)
	if err != nil {
		return
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_ = writeFileAtomic(path, data)
}

// startControlPoller 轮询请求文件并投递到主循环；返回停止函数。
func startControlPoller(reqPath string, cmdCh chan<- controlRequest) func() {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				data, err := os.ReadFile(reqPath)
				if err != nil {
					continue
				}
				_ = os.Remove(reqPath)
				var req controlRequest
				if json.Unmarshal(data, &req) != nil || req.ID == "" || req.Op == "" {
					continue
				}
				select {
				case cmdCh <- req:
				case <-done:
					return
				}
			}
		}
	}()
	return func() { close(done) }
}

// cleanControlFiles 清除残留的请求/响应文件（启动与停止时调用）。
func cleanControlFiles() {
	dir, err := daemon.StateDir()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if name == controlReqName || (strings.HasPrefix(name, "control.") && strings.HasSuffix(name, ".resp")) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}
