package cmd

import (
	"errors"
	"testing"
)

// TestFailureRegistryRoundTrip 校验失败登记的写入/读取/清除，
// 并确认凭据类失败被标记为 auth（前端据此弹出凭据修正窗口）。
// 通过重定向状态目录隔离测试，不触碰真实的 %LOCALAPPDATA%\sshtun。
func TestFailureRegistryRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("LOCALAPPDATA", tmp)
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)

	if got := failureSnapshot(); len(got) != 0 {
		t.Fatalf("空状态目录下应无失败登记，实际: %+v", got)
	}

	authErr := errors.New("SSH 握手/认证失败: ssh: unable to authenticate, attempted methods [none password]")
	recordFailure("家庭网络", authErr)
	recordFailure("办公室", errors.New("连接 1.2.3.4:22 失败: dial tcp: i/o timeout"))

	snap := failureSnapshot()
	if len(snap) != 2 {
		t.Fatalf("应有 2 条登记，实际 %d: %+v", len(snap), snap)
	}
	if snap["家庭网络"].Kind != failureAuth {
		t.Errorf("认证被拒应登记为 auth，实际 %q（%s）", snap["家庭网络"].Kind, snap["家庭网络"].Message)
	}
	if snap["办公室"].Kind != failureOther {
		t.Errorf("网络失败应登记为 other，实际 %q", snap["办公室"].Kind)
	}
	if snap["家庭网络"].Message == "" {
		t.Error("应保留原始错误信息供界面展示")
	}

	// 启动成功后清除对应记录，其余记录不受影响。
	clearFailure("家庭网络")
	snap = failureSnapshot()
	if _, ok := snap["家庭网络"]; ok {
		t.Error("已清除的记录不应再出现")
	}
	if len(snap) != 1 {
		t.Fatalf("只应清除一条，实际剩余 %d 条", len(snap))
	}

	// 幂等：清除不存在的记录不应报错。
	clearFailure("不存在")
	clearFailure("")
	recordFailure("", nil)
	if len(failureSnapshot()) != 1 {
		t.Fatal("空名/nil 不应产生记录")
	}
}
