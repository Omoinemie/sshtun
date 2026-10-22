package cmd

import "testing"

// 重启流程为「先 remove 旧会话再 add 同名新会话」：旧会话 tun2socks 的退出事件
// 会在新会话注册之后到达，必须按会话标识忽略，否则刚重启的隧道会被误停。
func TestExitEventIgnoresStaleSession(t *testing.T) {
	running := &tunnelSession{name: "office"}
	m := &runtimeManager{sessions: map[string]*tunnelSession{"office": running}}

	stale := exitEvent{name: "office", sess: &tunnelSession{name: "office"}}
	if m.isCurrent(stale) {
		t.Error("旧会话的残留退出事件不应命中当前会话（重启竞态）")
	}
	if !m.isCurrent(exitEvent{name: "office", sess: running}) {
		t.Error("当前会话的退出事件应命中")
	}

	m.remove("office")
	if m.isCurrent(exitEvent{name: "office", sess: running}) {
		t.Error("已停止隧道的退出事件应被忽略")
	}
	if m.isCurrent(exitEvent{name: "不存在", sess: running}) {
		t.Error("未登记隧道的退出事件应被忽略")
	}
}
