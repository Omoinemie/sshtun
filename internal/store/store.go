// Package store 使用 SQLite（纯 Go 驱动 modernc.org/sqlite）持久化隧道、
// 路由与端口转发配置。配置文件只保留基础配置，隧道等配置由本包管理。
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Omoinemie/sshtun/internal/config"
)

// Store 是数据库句柄。
type Store struct {
	db *sql.DB
}

// Route 是一条隧道路由（网段或单 IP）。
type Route struct {
	CIDR string
	// Kind: tunnel（走隧道）| bypass（强制直连）。
	Kind string
}

// 路由类型。
const (
	RouteKindTunnel = "tunnel"
	RouteKindBypass = "bypass"
)

// Forward 是一条端口转发规则。
type Forward struct {
	// Direction: local(-L) | remote(-R)。
	Direction  string
	BindAddr   string
	BindPort   int
	TargetHost string
	TargetPort int
	Enabled    bool
}

// 转发方向。
const (
	ForwardLocal  = "local"
	ForwardRemote = "remote"
)

// Tunnel 是一条 SSH 隧道的完整配置（SSH + TUN + 路由 + 转发）。
type Tunnel struct {
	ID int64
	// UID 是隧道的稳定标识：随机十六进制串，隧道改名后不变。
	// 界面与 API 用它区分隧道，Name 仅作为可改的显示名。
	UID     string
	Name    string
	Enabled bool

	SSHHost          string
	SSHPort          int
	SSHUser          string
	SSHAuth          string // password | key
	SSHPassword      string // enc:v3 密文
	SSHKeyFile       string
	SSHKeyPassphrase string
	SSHHostKey       string

	TunName    string
	TunAddress string
	TunMTU     int

	Routes   []Route
	Forwards []Forward
}

// ErrNotExist 表示按名字查找的隧道不存在。
var ErrNotExist = errors.New("the tunnel does not exist")

const schema = `
CREATE TABLE IF NOT EXISTS tunnels (
	id                  INTEGER PRIMARY KEY AUTOINCREMENT,
	uid                 TEXT    NOT NULL DEFAULT '',
	name                TEXT    NOT NULL UNIQUE,
	enabled             INTEGER NOT NULL DEFAULT 1,
	ssh_host            TEXT    NOT NULL,
	ssh_port            INTEGER NOT NULL DEFAULT 22,
	ssh_user            TEXT    NOT NULL DEFAULT 'root',
	ssh_auth            TEXT    NOT NULL DEFAULT 'key',
	ssh_password        TEXT    NOT NULL DEFAULT '',
	ssh_key_file        TEXT    NOT NULL DEFAULT '',
	ssh_key_passphrase  TEXT    NOT NULL DEFAULT '',
	ssh_host_key        TEXT    NOT NULL DEFAULT 'accept-new',
	tun_name            TEXT    NOT NULL,
	tun_address         TEXT    NOT NULL,
	tun_mtu             INTEGER NOT NULL DEFAULT 1500,
	created_at          TEXT    NOT NULL DEFAULT '',
	updated_at          TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS routes (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	tunnel_id INTEGER NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
	cidr      TEXT    NOT NULL,
	kind      TEXT    NOT NULL DEFAULT 'tunnel'
);

CREATE TABLE IF NOT EXISTS forwards (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	tunnel_id   INTEGER NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
	direction   TEXT    NOT NULL,
	bind_addr   TEXT    NOT NULL DEFAULT '',
	bind_port   INTEGER NOT NULL,
	target_host TEXT    NOT NULL,
	target_port INTEGER NOT NULL,
	enabled     INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_routes_tunnel   ON routes(tunnel_id);
CREATE INDEX IF NOT EXISTS idx_forwards_tunnel ON forwards(tunnel_id);
`

// Open 打开（或创建）数据库并确保表结构存在。
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("the database path is empty")
	}
	if dir := filepath.Dir(path); dir != "" {
		// 数据库含加密后的 SSH 凭据，目录与文件都收紧到仅当前用户可访问。
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("failed to create the database directory: %w", err)
		}
	}
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open the database: %w", err)
	}
	// 单连接串行化，规避 SQLite 写锁竞争。
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize the database tables: %w", err)
	}
	// 已存在的旧库可能是 0644，这里统一收紧。
	_ = os.Chmod(path, 0o600)
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// migrate 为旧库补齐新增列（SQLite 无 ADD COLUMN IF NOT EXISTS，需先探测列是否存在）。
// 当前仅 tunnels.uid：隧道改名后仍需稳定标识，故为每条隧道回填随机 UID。
func migrate(db *sql.DB) error {
	has, err := hasColumn(db, "tunnels", "uid")
	if err != nil {
		return err
	}
	if !has {
		if _, err := db.Exec(`ALTER TABLE tunnels ADD COLUMN uid TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("failed to upgrade the database (tunnels.uid): %w", err)
		}
	}
	// 回填：旧记录 uid 为空，逐条生成随机 UID。
	rows, err := db.Query(`SELECT id FROM tunnels WHERE uid = ''`)
	if err != nil {
		return fmt.Errorf("failed to upgrade the database (backfilling uid): %w", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	for _, id := range ids {
		if _, err := db.Exec(`UPDATE tunnels SET uid = ? WHERE id = ?`, newUID(), id); err != nil {
			return fmt.Errorf("failed to upgrade the database (backfilling uid): %w", err)
		}
	}
	return nil
}

// hasColumn 报告表中是否存在指定列。
func hasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, fmt.Errorf("failed to read the table schema: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid        int
			name, typ  string
			notNull    int
			dflt       any
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &primaryKey); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// newUID 生成隧道标识：随机 8 字节十六进制串（16 个字符）。
func newUID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 极端情况下退化为时间派生值（仍保证同机唯一）。
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// Close 关闭数据库。
func (s *Store) Close() error { return s.db.Close() }

// ListTunnels 返回全部隧道（含路由与转发），按名字排序。
func (s *Store) ListTunnels() ([]*Tunnel, error) {
	rows, err := s.db.Query(`SELECT id, uid, name, enabled,
		ssh_host, ssh_port, ssh_user, ssh_auth, ssh_password, ssh_key_file,
		ssh_key_passphrase, ssh_host_key,
		tun_name, tun_address, tun_mtu
		FROM tunnels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Tunnel
	for rows.Next() {
		t, err := scanTunnel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.loadAllChildren(out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetTunnel 按名字返回单条隧道（含路由与转发）。
func (s *Store) GetTunnel(name string) (*Tunnel, error) {
	row := s.db.QueryRow(`SELECT id, uid, name, enabled,
		ssh_host, ssh_port, ssh_user, ssh_auth, ssh_password, ssh_key_file,
		ssh_key_passphrase, ssh_host_key,
		tun_name, tun_address, tun_mtu
		FROM tunnels WHERE name = ?`, name)
	t, err := scanTunnel(row)
	if err != nil {
		return nil, err
	}
	if err := s.loadChildren(t); err != nil {
		return nil, err
	}
	return t, nil
}

// GetTunnelByUID 按稳定标识返回单条隧道（含路由与转发）；隧道改名后依然可用。
func (s *Store) GetTunnelByUID(uid string) (*Tunnel, error) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return nil, ErrNotExist
	}
	row := s.db.QueryRow(`SELECT id, uid, name, enabled,
		ssh_host, ssh_port, ssh_user, ssh_auth, ssh_password, ssh_key_file,
		ssh_key_passphrase, ssh_host_key,
		tun_name, tun_address, tun_mtu
		FROM tunnels WHERE uid = ?`, uid)
	t, err := scanTunnel(row)
	if err != nil {
		return nil, err
	}
	if err := s.loadChildren(t); err != nil {
		return nil, err
	}
	return t, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanTunnel(sc scanner) (*Tunnel, error) {
	var (
		t       Tunnel
		enabled int
	)
	err := sc.Scan(&t.ID, &t.UID, &t.Name, &enabled,
		&t.SSHHost, &t.SSHPort, &t.SSHUser, &t.SSHAuth, &t.SSHPassword, &t.SSHKeyFile,
		&t.SSHKeyPassphrase, &t.SSHHostKey,
		&t.TunName, &t.TunAddress, &t.TunMTU)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	t.Enabled = enabled != 0
	return &t, nil
}

// loadAllChildren 一次性取回全部路由与转发后按 tunnel_id 分组，
// 避免隧道数量增长时产生 1+2N 次查询。
func (s *Store) loadAllChildren(list []*Tunnel) error {
	if len(list) == 0 {
		return nil
	}
	byID := make(map[int64]*Tunnel, len(list))
	for _, t := range list {
		byID[t.ID] = t
	}

	rrows, err := s.db.Query(`SELECT tunnel_id, cidr, kind FROM routes ORDER BY id`)
	if err != nil {
		return err
	}
	defer rrows.Close()
	for rrows.Next() {
		var (
			tid int64
			r   Route
		)
		if err := rrows.Scan(&tid, &r.CIDR, &r.Kind); err != nil {
			return err
		}
		t, ok := byID[tid]
		if !ok {
			continue
		}
		if r.Kind == "" {
			r.Kind = RouteKindTunnel
		}
		t.Routes = append(t.Routes, r)
	}
	if err := rrows.Err(); err != nil {
		return err
	}
	_ = rrows.Close()

	frows, err := s.db.Query(`SELECT tunnel_id, direction, bind_addr, bind_port, target_host, target_port, enabled
		FROM forwards ORDER BY id`)
	if err != nil {
		return err
	}
	defer frows.Close()
	for frows.Next() {
		var (
			tid     int64
			f       Forward
			enabled int
		)
		if err := frows.Scan(&tid, &f.Direction, &f.BindAddr, &f.BindPort, &f.TargetHost, &f.TargetPort, &enabled); err != nil {
			return err
		}
		t, ok := byID[tid]
		if !ok {
			continue
		}
		f.Enabled = enabled != 0
		t.Forwards = append(t.Forwards, f)
	}
	return frows.Err()
}

func (s *Store) loadChildren(t *Tunnel) error {
	rrows, err := s.db.Query(`SELECT cidr, kind FROM routes WHERE tunnel_id = ? ORDER BY id`, t.ID)
	if err != nil {
		return err
	}
	defer rrows.Close()
	for rrows.Next() {
		var r Route
		if err := rrows.Scan(&r.CIDR, &r.Kind); err != nil {
			return err
		}
		if r.Kind == "" {
			r.Kind = RouteKindTunnel
		}
		t.Routes = append(t.Routes, r)
	}
	if err := rrows.Err(); err != nil {
		return err
	}

	frows, err := s.db.Query(`SELECT direction, bind_addr, bind_port, target_host, target_port, enabled
		FROM forwards WHERE tunnel_id = ? ORDER BY id`, t.ID)
	if err != nil {
		return err
	}
	defer frows.Close()
	for frows.Next() {
		var (
			f       Forward
			enabled int
		)
		if err := frows.Scan(&f.Direction, &f.BindAddr, &f.BindPort, &f.TargetHost, &f.TargetPort, &enabled); err != nil {
			return err
		}
		f.Enabled = enabled != 0
		t.Forwards = append(t.Forwards, f)
	}
	return frows.Err()
}

// UpsertTunnel 新增或更新隧道，并整体替换其路由与转发子表。
//
// 定位规则：优先按 UID（隧道改名后仍能定位到同一条记录）；
// 没有 UID 时按名字定位，名字不存在则视为新增。
// 更新时名字可改，UID 保持不变。
func (s *Store) UpsertTunnel(t *Tunnel) error {
	if t.Name == "" {
		return errors.New("the tunnel name must not be empty")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Format(time.RFC3339)
	var (
		existingID  int64
		existingUID string
	)
	if uid := strings.TrimSpace(t.UID); uid != "" {
		err = tx.QueryRow(`SELECT id, uid FROM tunnels WHERE uid = ?`, uid).Scan(&existingID, &existingUID)
	} else {
		err = tx.QueryRow(`SELECT id, uid FROM tunnels WHERE name = ?`, t.Name).Scan(&existingID, &existingUID)
	}
	switch {
	case errors.Is(err, sql.ErrNoRows):
		uid := newUID()
		for i := 0; i < 5; i++ { // 极小概率撞车，重试
			var n int
			if e := tx.QueryRow(`SELECT COUNT(1) FROM tunnels WHERE uid = ?`, uid).Scan(&n); e != nil || n > 0 {
				uid = newUID()
				continue
			}
			break
		}
		res, ierr := tx.Exec(`INSERT INTO tunnels
			(uid, name, enabled, ssh_host, ssh_port, ssh_user, ssh_auth, ssh_password, ssh_key_file,
			 ssh_key_passphrase, ssh_host_key, tun_name, tun_address, tun_mtu, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			uid, t.Name, boolInt(t.Enabled), t.SSHHost, t.SSHPort, t.SSHUser, t.SSHAuth, t.SSHPassword, t.SSHKeyFile,
			t.SSHKeyPassphrase, t.SSHHostKey,
			t.TunName, t.TunAddress, t.TunMTU, now, now)
		if ierr != nil {
			return ierr
		}
		id, ierr := res.LastInsertId()
		if ierr != nil {
			return ierr
		}
		t.ID = id
		t.UID = uid
	case err != nil:
		return err
	default:
		if _, uerr := tx.Exec(`UPDATE tunnels SET
			name=?, enabled=?, ssh_host=?, ssh_port=?, ssh_user=?, ssh_auth=?, ssh_password=?, ssh_key_file=?,
			ssh_key_passphrase=?, ssh_host_key=?,
			tun_name=?, tun_address=?, tun_mtu=?, updated_at=?
			WHERE id=?`,
			t.Name, boolInt(t.Enabled), t.SSHHost, t.SSHPort, t.SSHUser, t.SSHAuth, t.SSHPassword, t.SSHKeyFile,
			t.SSHKeyPassphrase, t.SSHHostKey,
			t.TunName, t.TunAddress, t.TunMTU, now, existingID); uerr != nil {
			return uerr
		}
		t.ID = existingID
		t.UID = existingUID
	}

	if _, err := tx.Exec(`DELETE FROM routes WHERE tunnel_id = ?`, t.ID); err != nil {
		return err
	}
	for _, r := range t.Routes {
		kind := r.Kind
		if kind == "" {
			kind = RouteKindTunnel
		}
		if _, err := tx.Exec(`INSERT INTO routes(tunnel_id, cidr, kind) VALUES (?,?,?)`, t.ID, r.CIDR, kind); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`DELETE FROM forwards WHERE tunnel_id = ?`, t.ID); err != nil {
		return err
	}
	for _, f := range t.Forwards {
		if _, err := tx.Exec(`INSERT INTO forwards(tunnel_id, direction, bind_addr, bind_port, target_host, target_port, enabled)
			VALUES (?,?,?,?,?,?,?)`,
			t.ID, f.Direction, f.BindAddr, f.BindPort, f.TargetHost, f.TargetPort, boolInt(f.Enabled)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteTunnel 按名字删除隧道及其子表（级联）。
func (s *Store) DeleteTunnel(name string) error {
	res, err := s.db.Exec(`DELETE FROM tunnels WHERE name = ?`, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotExist
	}
	return nil
}

// SetEnabled 启用/停用指定隧道。
func (s *Store) SetEnabled(name string, enabled bool) error {
	res, err := s.db.Exec(`UPDATE tunnels SET enabled=?, updated_at=? WHERE name=?`,
		boolInt(enabled), time.Now().Format(time.RFC3339), name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotExist
	}
	return nil
}

// UpdateUser 更新指定隧道的登录用户名。
func (s *Store) UpdateUser(name, user string) error {
	res, err := s.db.Exec(`UPDATE tunnels SET ssh_user=?, updated_at=? WHERE name=?`,
		user, time.Now().Format(time.RFC3339), name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotExist
	}
	return nil
}

// UpdatePassword 更新指定隧道的（加密后的）密码。
func (s *Store) UpdatePassword(name, encPassword string) error {
	res, err := s.db.Exec(`UPDATE tunnels SET ssh_password=?, updated_at=? WHERE name=?`,
		encPassword, time.Now().Format(time.RFC3339), name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotExist
	}
	return nil
}

// RuntimeConfig 依据基础配置构造该隧道的运行时单隧道配置，
// 供 sshclient / routing / forwarder / tun2socks 复用。
func (t *Tunnel) RuntimeConfig(base *config.Config) *config.Config {
	c := &config.Config{
		App:       base.App,
		Tun2socks: base.Tun2socks,
		Log:       base.Log,
		Path:      base.Path,
	}
	c.SSH = config.SSHConfig{
		Host:          t.SSHHost,
		Port:          t.SSHPort,
		User:          t.SSHUser,
		Auth:          t.SSHAuth,
		Password:      t.SSHPassword,
		KeyFile:       t.SSHKeyFile,
		KeyPassphrase: t.SSHKeyPassphrase,
		HostKey:       t.SSHHostKey,
		// 隧道统一参数取自基础配置（[ssh] 段），不再随隧道持久化。
		Keepalive:      base.SSH.Keepalive,
		ConnectTimeout: base.SSH.ConnectTimeout,
	}
	c.Tun = config.TunConfig{
		Enabled: true,
		Name:    t.TunName,
		Address: t.TunAddress,
		MTU:     t.TunMTU,
	}
	for _, r := range t.Routes {
		if r.Kind == RouteKindBypass {
			c.Tun.Bypass = append(c.Tun.Bypass, r.CIDR)
		} else {
			c.Tun.Routes = append(c.Tun.Routes, r.CIDR)
		}
	}
	for _, f := range t.Forwards {
		if !f.Enabled {
			continue
		}
		rule := config.ForwardRule{
			BindAddr: f.BindAddr,
			BindPort: f.BindPort,
			Target:   joinHostPort(f.TargetHost, f.TargetPort),
			Raw:      formatForwardRaw(f),
		}
		switch f.Direction {
		case ForwardRemote:
			c.Forwards.Remote = append(c.Forwards.Remote, rule)
		default:
			c.Forwards.Local = append(c.Forwards.Local, rule)
		}
	}
	c.ApplyTunnelDefaults()
	c.ResolveSSHPaths()
	return c
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// formatForwardRaw 生成便于展示的转发串：[bind_addr:]bind_port:target_host:target_port。
func formatForwardRaw(f Forward) string {
	head := strconv.Itoa(f.BindPort)
	if f.BindAddr != "" {
		head = f.BindAddr + ":" + head
	}
	return head + ":" + joinHostPort(f.TargetHost, f.TargetPort)
}
