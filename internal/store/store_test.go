package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strconv"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/Omoinemie/sshtun/internal/config"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "sshtun.db"))
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sampleTunnel() *Tunnel {
	return &Tunnel{
		Name:       "office",
		Enabled:    true,
		SSHHost:    "203.0.113.10",
		SSHPort:    22,
		SSHUser:    "root",
		SSHAuth:    "key",
		SSHKeyFile: "id_rsa",
		SSHHostKey: "none",
		TunName:    "sshtun0",
		TunAddress: "198.18.0.1/30",
		TunMTU:     1500,
		Routes: []Route{
			{CIDR: "10.8.0.0/16", Kind: RouteKindTunnel},
			{CIDR: "192.168.1.0/24", Kind: RouteKindBypass},
		},
		Forwards: []Forward{
			{Direction: ForwardLocal, BindPort: 8443, TargetHost: "10.1.2.3", TargetPort: 443, Enabled: true},
			{Direction: ForwardRemote, BindPort: 9090, TargetHost: "127.0.0.1", TargetPort: 8080, Enabled: true},
		},
	}
}

// TestRenameByUID 隧道改名后 UID 不变，路由与转发等关联数据保持不变。
func TestRenameByUID(t *testing.T) {
	s := openTemp(t)
	in := sampleTunnel()
	if err := s.UpsertTunnel(in); err != nil {
		t.Fatalf("Upsert 失败: %v", err)
	}
	if in.UID == "" {
		t.Fatal("新建隧道应自动分配 UID")
	}
	uid := in.UID

	// 按 UID 改名
	in.Name = "office-new"
	if err := s.UpsertTunnel(in); err != nil {
		t.Fatalf("改名失败: %v", err)
	}
	if in.UID != uid {
		t.Errorf("改名后 UID 应不变: %s != %s", in.UID, uid)
	}
	got, err := s.GetTunnelByUID(uid)
	if err != nil {
		t.Fatalf("按 UID 查询失败: %v", err)
	}
	if got.Name != "office-new" {
		t.Errorf("改名未生效: %s", got.Name)
	}
	if len(got.Routes) != len(sampleTunnel().Routes) {
		t.Errorf("改名后路由应保留: %+v", got.Routes)
	}
	if len(got.Forwards) != len(sampleTunnel().Forwards) {
		t.Errorf("改名后端口转发应保留: %+v", got.Forwards)
	}
	// 旧名字不应再命中
	if _, err := s.GetTunnel("office"); !errors.Is(err, ErrNotExist) {
		t.Errorf("旧名字应查不到: %v", err)
	}
}

// TestUIDUnique 每条隧道的 UID 互不相同。
func TestUIDUnique(t *testing.T) {
	s := openTemp(t)
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		tn := sampleTunnel()
		tn.Name = "t" + strconv.Itoa(i)
		if err := s.UpsertTunnel(tn); err != nil {
			t.Fatalf("Upsert 失败: %v", err)
		}
		if tn.UID == "" {
			t.Fatal("应分配 UID")
		}
		if seen[tn.UID] {
			t.Fatalf("UID 重复: %s", tn.UID)
		}
		seen[tn.UID] = true
	}
}

// TestMigrateUID 旧库（无 uid 列）升级后自动补列并回填 UID。
func TestMigrateUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	// 造一个与旧版本结构一致的库
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("打开旧库失败: %v", err)
	}
	if _, err := old.Exec(`CREATE TABLE tunnels (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		enabled INTEGER NOT NULL DEFAULT 1,
		ssh_host TEXT NOT NULL, ssh_port INTEGER NOT NULL DEFAULT 22,
		ssh_user TEXT NOT NULL DEFAULT 'root', ssh_auth TEXT NOT NULL DEFAULT 'key',
		ssh_password TEXT NOT NULL DEFAULT '', ssh_key_file TEXT NOT NULL DEFAULT '',
		ssh_key_passphrase TEXT NOT NULL DEFAULT '', ssh_host_key TEXT NOT NULL DEFAULT 'accept-new',
		tun_name TEXT NOT NULL, tun_address TEXT NOT NULL, tun_mtu INTEGER NOT NULL DEFAULT 1500,
		created_at TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatalf("建旧表失败: %v", err)
	}
	if _, err := old.Exec(`INSERT INTO tunnels (name, ssh_host, tun_name, tun_address)
		VALUES ('legacy','1.2.3.4','sshtun9','198.18.9.1/30')`); err != nil {
		t.Fatalf("插入旧记录失败: %v", err)
	}
	_ = old.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("打开旧库失败: %v", err)
	}
	defer s.Close()
	got, err := s.GetTunnel("legacy")
	if err != nil {
		t.Fatalf("旧记录查询失败: %v", err)
	}
	if got.UID == "" {
		t.Error("旧记录的 UID 应被回填")
	}
	byUID, err := s.GetTunnelByUID(got.UID)
	if err != nil || byUID.Name != "legacy" {
		t.Errorf("按回填的 UID 查询失败: %v %+v", err, byUID)
	}
}

func TestUpsertAndGet(t *testing.T) {
	s := openTemp(t)
	in := sampleTunnel()
	if err := s.UpsertTunnel(in); err != nil {
		t.Fatalf("Upsert 失败: %v", err)
	}
	if in.ID == 0 {
		t.Fatalf("Upsert 后应回填 ID")
	}

	got, err := s.GetTunnel("office")
	if err != nil {
		t.Fatalf("GetTunnel 失败: %v", err)
	}
	if got.SSHHost != "203.0.113.10" || got.TunName != "sshtun0" {
		t.Errorf("字段不符: %+v", got)
	}
	if len(got.Routes) != 2 || len(got.Forwards) != 2 {
		t.Fatalf("子表数量错误: routes=%d forwards=%d", len(got.Routes), len(got.Forwards))
	}

	// 再次 Upsert：替换子表，不重复
	in.Routes = in.Routes[:1]
	in.Forwards = nil
	in.SSHPort = 2222
	if err := s.UpsertTunnel(in); err != nil {
		t.Fatalf("二次 Upsert 失败: %v", err)
	}
	got, err = s.GetTunnel("office")
	if err != nil {
		t.Fatal(err)
	}
	if got.SSHPort != 2222 || len(got.Routes) != 1 || len(got.Forwards) != 0 {
		t.Errorf("二次 Upsert 未按预期替换: %+v", got)
	}

	if _, err := s.GetTunnel("missing"); err != ErrNotExist {
		t.Errorf("不存在的隧道应返回 ErrNotExist, got %v", err)
	}
}

func TestDeleteAndEnable(t *testing.T) {
	s := openTemp(t)
	if err := s.UpsertTunnel(sampleTunnel()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnabled("office", false); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetTunnel("office")
	if got.Enabled {
		t.Errorf("应已停用")
	}
	all, err := s.ListTunnels()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Enabled {
		t.Errorf("停用后应只有一条停用的隧道, got %+v", all)
	}
	if err := s.DeleteTunnel("office"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTunnel("office"); err != ErrNotExist {
		t.Errorf("重复删除应返回 ErrNotExist, got %v", err)
	}
}

func TestRuntimeConfigMapping(t *testing.T) {
	s := openTemp(t)
	in := sampleTunnel()
	// 绝对路径，避免相对解析；须用当前平台的真绝对路径：
	// Windows 下 "/abs/id_rsa" 缺盘符并非绝对路径，会被拼到配置目录下。
	absKey, err := filepath.Abs(filepath.Join("abs", "id_rsa"))
	if err != nil {
		t.Fatalf("Abs 失败: %v", err)
	}
	in.SSHKeyFile = absKey
	if err := s.UpsertTunnel(in); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetTunnel("office")

	base := &config.Config{Path: "/etc/sshtun/setting.conf"}
	base.App.DB = "/tmp/x.db"
	base.Log.Level = "info"
	rt := got.RuntimeConfig(base)

	if rt.SSH.Host != "203.0.113.10" || rt.SSH.KeyFile != absKey {
		t.Errorf("SSH 映射错误: %+v", rt.SSH)
	}
	if rt.SSH.Port != 22 || rt.SSH.Keepalive != 30 {
		t.Errorf("SSH 缺省/字段错误: %+v", rt.SSH)
	}
	if rt.Tun.Name != "sshtun0" || rt.Tun.Address != "198.18.0.1/30" || rt.Tun.MTU != 1500 {
		t.Errorf("TUN 映射错误: %+v", rt.Tun)
	}
	if len(rt.Tun.Routes) != 1 || rt.Tun.Routes[0] != "10.8.0.0/16" {
		t.Errorf("routes 映射错误: %v", rt.Tun.Routes)
	}
	if len(rt.Tun.Bypass) != 1 || rt.Tun.Bypass[0] != "192.168.1.0/24" {
		t.Errorf("bypass 映射错误: %v", rt.Tun.Bypass)
	}
	if len(rt.Forwards.Local) != 1 || rt.Forwards.Local[0].BindPort != 8443 {
		t.Errorf("local 转发映射错误: %+v", rt.Forwards.Local)
	}
	if len(rt.Forwards.Remote) != 1 || rt.Forwards.Remote[0].BindPort != 9090 {
		t.Errorf("remote 转发映射错误: %+v", rt.Forwards.Remote)
	}
	if rt.Log.Level != "info" || rt.App.DB != "/tmp/x.db" {
		t.Errorf("基础字段未继承: %+v", rt)
	}
}

func TestListTunnels(t *testing.T) {
	s := openTemp(t)
	for _, name := range []string{"b", "a", "c"} {
		tun := sampleTunnel()
		tun.Name = name
		if err := s.UpsertTunnel(tun); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.ListTunnels()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].Name != "a" || all[2].Name != "c" {
		t.Errorf("应按名字排序: %+v", all)
	}
}
