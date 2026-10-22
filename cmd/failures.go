package cmd

// 启动失败登记：把每条隧道最近一次启动失败的原因落到状态目录的 failures.json，
// 供 Web/GUI 界面（GET /api/failures）读取后提示用户修正凭据并重试。
//
// 采用文件而非内存：启动可能发生在另一个进程（CLI `sshtun start` 拉起的实例、
// 或经控制通道由既有实例执行），而 Web 界面所在进程并不知道失败原因；
// 共享同一份文件即可跨进程传递。隧道启动成功后清除对应记录。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/Omoinemie/sshtun/internal/daemon"
	"github.com/Omoinemie/sshtun/internal/logging"
)

// failuresFileName 是失败登记文件名（位于 daemon 状态目录下）。
const failuresFileName = "failures.json"

// 失败分类：auth 表示凭据类失败（用户可重填凭据后重试），other 表示其余失败。
const (
	failureAuth  = "auth"
	failureOther = "other"
)

// tunnelFailure 是一条隧道最近一次启动失败的分类信息。
type tunnelFailure struct {
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

// failuresPath 返回失败登记文件路径。
func failuresPath() (string, error) {
	dir, err := daemon.StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, failuresFileName), nil
}

// loadFailures 读取失败登记表；文件不存在或损坏时返回空表。
func loadFailures() map[string]tunnelFailure {
	path, err := failuresPath()
	if err != nil {
		return map[string]tunnelFailure{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]tunnelFailure{}
	}
	var m map[string]tunnelFailure
	if err := json.Unmarshal(data, &m); err != nil {
		return map[string]tunnelFailure{}
	}
	if m == nil {
		m = map[string]tunnelFailure{}
	}
	return m
}

// saveFailures 原子写回失败登记表；失败仅告警（不影响隧道本身）。
func saveFailures(m map[string]tunnelFailure) {
	path, err := failuresPath()
	if err != nil {
		logging.Debug("the failure directory is unusable, skipping the record", "err", err)
		return
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	if err := writeFileAtomic(path, data); err != nil {
		logging.Debug("failed to write the failure registry file", "err", err)
	}
}

// recordFailure 登记一条隧道的启动失败；凭据类失败单独标记。
func recordFailure(name string, err error) {
	if name == "" || err == nil {
		return
	}
	f := tunnelFailure{Kind: failureOther, Message: err.Error(), At: time.Now()}
	if isCredentialError(err) {
		f.Kind = failureAuth
	}
	m := loadFailures()
	m[name] = f
	saveFailures(m)
	logging.Debug("recorded the tunnel start failure", "tunnel", name, "kind", f.Kind)
}

// clearFailure 在隧道启动成功后清除其失败登记。
func clearFailure(name string) {
	if name == "" {
		return
	}
	m := loadFailures()
	if _, ok := m[name]; !ok {
		return
	}
	delete(m, name)
	saveFailures(m)
}

// failureSnapshot 返回当前全部失败登记。
func failureSnapshot() map[string]tunnelFailure { return loadFailures() }
