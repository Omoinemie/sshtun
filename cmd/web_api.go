package cmd

// Web 管理界面的本地 JSON API。
// 除 /api/login、/api/logout、/api/session 外，均需登录后的会话令牌（X-Token 头 / ?token= / Cookie）。
// 免登录模式（回环地址且未设置密码）下直接放行。

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/daemon"
	"github.com/Omoinemie/sshtun/internal/secret"
	"github.com/Omoinemie/sshtun/internal/store"
	"github.com/Omoinemie/sshtun/internal/version"
)

type webAPI struct {
	cfg       *config.Config
	sessions  *sessionStore
	username  string
	password  string
	needLogin bool
	// staticToken 是 GUI 托管实例的随机访问令牌；非空时所有 API 请求都必须携带它，
	// 即便进程以管理员权限运行、且监听在回环地址。
	staticToken string
	// managed 表示本实例由 sshtun-gui 拉起：需要管理员权限时交由 GUI 自我提权重启处理。
	managed bool

	// db 复用同一个数据库句柄：避免每个请求都重新建连接池并执行 schema。
	dbOnce sync.Once
	db     *store.Store
	dbErr  error

	mu sync.Mutex
	// pending 是一次等待 GUI 处理的提权请求（GUI 轮询 /api/session 取得后重启自身）。
	pending *elevateReq

	// 登录失败节流：按来源 IP 记录连续失败次数与锁定截止时间。
	loginMu    sync.Mutex
	loginFails map[string]*loginFailure
}

// loginFailure 记录单个来源的连续登录失败次数。
type loginFailure struct {
	count    int
	lockedTo time.Time
}

// 登录失败阈值与锁定上限。
const (
	loginFailThreshold = 5
	loginLockBase      = 30 * time.Second
	loginLockMax       = 5 * time.Minute
)

// loginLocked 报告来源 IP 当前是否处于锁定期；并在允许时返回 nil。
func (h *webAPI) loginLocked(remote string) error {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()
	f := h.loginFails[remote]
	if f == nil {
		return nil
	}
	if time.Now().Before(f.lockedTo) {
		return fmt.Errorf("登录失败次数过多，请于 %s 后重试", time.Until(f.lockedTo).Round(time.Second))
	}
	return nil
}

// recordLoginFailure 累计失败次数，达到阈值后按指数退避锁定。
func (h *webAPI) recordLoginFailure(remote string) {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()
	if h.loginFails == nil {
		h.loginFails = make(map[string]*loginFailure)
	}
	f := h.loginFails[remote]
	if f == nil {
		f = &loginFailure{}
		h.loginFails[remote] = f
	}
	f.count++
	if f.count >= loginFailThreshold {
		lock := loginLockBase << uint(f.count-loginFailThreshold)
		if lock > loginLockMax || lock <= 0 {
			lock = loginLockMax
		}
		f.lockedTo = time.Now().Add(lock)
	}
}

// resetLoginFailure 在登录成功后清除该来源的失败记录。
func (h *webAPI) resetLoginFailure(remote string) {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()
	delete(h.loginFails, remote)
}

// elevateReq 是前端请求提权时携带的待执行动作，供 GUI 提权重启后自动续跑。
type elevateReq struct {
	Action string   `json:"action"`
	Names  []string `json:"names"`
}

func (h *webAPI) register(mux *http.ServeMux) {
	// 登录相关端点无需鉴权。
	mux.HandleFunc("POST /api/login", h.handleLogin)
	mux.HandleFunc("POST /api/logout", h.handleLogout)
	mux.HandleFunc("GET /api/session", h.handleSession)

	mux.HandleFunc("GET /api/overview", h.auth(h.handleOverview))
	mux.HandleFunc("GET /api/tunnels", h.auth(h.handleTunnelsList))
	mux.HandleFunc("POST /api/tunnels", h.auth(h.handleTunnelUpsert))
	mux.HandleFunc("GET /api/tunnels/{name}", h.auth(h.handleTunnelGet))
	mux.HandleFunc("DELETE /api/tunnels/{name}", h.auth(h.handleTunnelDelete))
	mux.HandleFunc("POST /api/tunnels/{name}/enabled", h.auth(h.handleTunnelEnabled))
	mux.HandleFunc("POST /api/tunnels/{name}/routes", h.auth(h.handleRouteAdd))
	mux.HandleFunc("DELETE /api/tunnels/{name}/routes", h.auth(h.handleRouteDelete))
	mux.HandleFunc("POST /api/tunnels/{name}/forwards", h.auth(h.handleForwardAdd))
	mux.HandleFunc("DELETE /api/tunnels/{name}/forwards", h.auth(h.handleForwardDelete))
	mux.HandleFunc("POST /api/actions/{op}", h.auth(h.handleAction))
	mux.HandleFunc("POST /api/elevate", h.auth(h.handleElevate))
	mux.HandleFunc("POST /api/shutdown", h.shutdownAuth(h.handleShutdown))
	mux.HandleFunc("GET /api/stats", h.auth(h.handleStats))
	mux.HandleFunc("GET /api/logs", h.auth(h.handleLogs))
	mux.HandleFunc("GET /api/failures", h.auth(h.handleFailures))
	mux.HandleFunc("GET /api/settings", h.auth(h.handleSettingsGet))
	mux.HandleFunc("POST /api/settings", h.auth(h.handleSettingsSave))
}

// auth 校验访问令牌；托管实例要求静态令牌，登录模式要求会话令牌，
// 免登录模式（回环 + 未设密码）直接放行。
func (h *webAPI) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.staticToken != "" {
			if !constantEqual(h.tokenFrom(r), h.staticToken) {
				writeErr(w, http.StatusUnauthorized, errors.New("无效的访问令牌"))
				return
			}
			next(w, r)
			return
		}
		if !h.needLogin {
			next(w, r)
			return
		}
		if !h.sessions.valid(h.tokenFrom(r)) {
			writeErr(w, http.StatusUnauthorized, errors.New("未登录或会话已过期"))
			return
		}
		next(w, r)
	}
}

// tokenFrom 依次从 X-Token 头与 Cookie 中提取访问令牌。
// 不接受 URL 查询参数：令牌出现在地址/日志/Referer 中容易被泄漏。
func (h *webAPI) tokenFrom(r *http.Request) string {
	if t := r.Header.Get("X-Token"); t != "" {
		return t
	}
	if c, err := r.Cookie(sessionCookieName); err == nil {
		return c.Value
	}
	return ""
}

/* ------------------------------- 登录/会话 ------------------------------- */

func (h *webAPI) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	if !h.needLogin {
		writeJSON(w, map[string]any{"ok": true, "token": "", "username": h.username, "needLogin": false, "expiresIn": 0})
		return
	}
	remote := stripPort(r.RemoteAddr)
	if err := h.loginLocked(remote); err != nil {
		writeErr(w, http.StatusTooManyRequests, err)
		return
	}
	if !constantEqual(strings.TrimSpace(in.Username), h.username) || !constantEqual(in.Password, h.password) {
		h.recordLoginFailure(remote)
		writeErr(w, http.StatusUnauthorized, errors.New("用户名或密码错误"))
		return
	}
	h.resetLoginFailure(remote)
	tok, expires := h.sessions.issue(h.username)
	if tok == "" {
		writeErr(w, http.StatusInternalServerError, errors.New("生成会话令牌失败"))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   expires,
	})
	writeJSON(w, map[string]any{"ok": true, "token": tok, "username": h.username, "needLogin": true, "expiresIn": expires})
}

func (h *webAPI) handleLogout(w http.ResponseWriter, r *http.Request) {
	h.sessions.revoke(h.tokenFrom(r))
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, map[string]any{"ok": true})
}

// handleSession 供前端引导：报告是否需要登录、当前是否已认证等。
// 该端点无需鉴权，因此只暴露非敏感信息；elevate 仅在有 GUI 提权请求时非空。
func (h *webAPI) handleSession(w http.ResponseWriter, r *http.Request) {
	authed := false
	switch {
	case h.staticToken != "":
		authed = constantEqual(h.tokenFrom(r), h.staticToken)
	case h.needLogin:
		authed = h.sessions.valid(h.tokenFrom(r))
	default:
		authed = true
	}

	// 提权待办只对已认证调用方可见，避免免登录回环模式下泄漏待执行动作。
	var pending *elevateReq
	if authed {
		h.mu.Lock()
		if h.pending != nil {
			cp := *h.pending
			pending = &cp
		}
		h.mu.Unlock()
	}

	writeJSON(w, map[string]any{
		"authed":        authed,
		"needLogin":     h.needLogin,
		"tokenRequired": h.staticToken != "",
		"username":      h.username,
		"privileged":    hasPrivileges(),
		"version":       version.Version,
		"managed":       h.managed,
		"platform":      runtime.GOOS,
		"elevate":       pending,
		// language/theme 为空表示自动：客户端按自身系统语言/主题选择。
		"language": h.cfg.Web.Language,
		"theme":    h.cfg.Web.Theme,
	})
}

/* --------------------------------- 模型 --------------------------------- */

type apiRoute struct {
	CIDR string `json:"cidr"`
	Kind string `json:"kind"`
}

type apiForward struct {
	Direction  string `json:"direction"`
	BindAddr   string `json:"bindAddr"`
	BindPort   int    `json:"bindPort"`
	TargetHost string `json:"targetHost"`
	TargetPort int    `json:"targetPort"`
	Enabled    bool   `json:"enabled"`
}

type apiTunnel struct {
	// UID 是隧道稳定标识（隐藏，不在界面展示）：隧道改名后仍用它定位。
	UID               string `json:"uid"`
	Name              string `json:"name"`
	Enabled           bool   `json:"enabled"`
	Running           bool   `json:"running"`
	SSHHost           string `json:"sshHost"`
	SSHPort           int    `json:"sshPort"`
	SSHUser           string `json:"sshUser"`
	SSHAuth           string `json:"sshAuth"`
	HasPassword       bool   `json:"hasPassword"`
	PasswordEncrypted bool   `json:"passwordEncrypted"`
	SSHKeyFile        string `json:"sshKeyFile"`
	SSHHostKey        string `json:"sshHostKey"`
	TunName           string `json:"tunName"`
	TunAddress        string `json:"tunAddress"`
	TunMTU            int    `json:"tunMtu"`
	// PeerIP 是运行中隧道 SSH 实际连到的对端 IP（v4 或 v6）；未运行时为空。
	PeerIP   string       `json:"peerIP"`
	Routes   []apiRoute   `json:"routes"`
	Forwards []apiForward `json:"forwards"`
}

func toAPITunnel(t *store.Tunnel, running bool, peerIP string) apiTunnel {
	out := apiTunnel{
		UID: t.UID, Name: t.Name, Enabled: t.Enabled, Running: running,
		SSHHost: t.SSHHost, SSHPort: t.SSHPort, SSHUser: t.SSHUser, SSHAuth: t.SSHAuth,
		HasPassword: t.SSHPassword != "", PasswordEncrypted: secret.IsEncrypted(t.SSHPassword),
		SSHKeyFile: t.SSHKeyFile, SSHHostKey: t.SSHHostKey,
		TunName: t.TunName, TunAddress: t.TunAddress, TunMTU: t.TunMTU,
		PeerIP:   peerIP,
		Routes:   make([]apiRoute, 0, len(t.Routes)),
		Forwards: make([]apiForward, 0, len(t.Forwards)),
	}
	for _, r := range t.Routes {
		out.Routes = append(out.Routes, apiRoute{CIDR: r.CIDR, Kind: r.Kind})
	}
	for _, f := range t.Forwards {
		out.Forwards = append(out.Forwards, apiForward{
			Direction: f.Direction, BindAddr: f.BindAddr, BindPort: f.BindPort,
			TargetHost: f.TargetHost, TargetPort: f.TargetPort, Enabled: f.Enabled,
		})
	}
	return out
}

/* --------------------------------- 概览 --------------------------------- */

// store 返回复用的数据库句柄（首次调用时打开，此后全进程共享）。
// 复用可避免每个请求都重新建立连接池并执行一次 schema。
func (h *webAPI) store() (*store.Store, error) {
	h.dbOnce.Do(func() { h.db, h.dbErr = store.Open(h.cfg.App.DB) })
	return h.db, h.dbErr
}

// CloseStore 关闭复用的数据库句柄（服务退出时调用）。
func (h *webAPI) CloseStore() {
	if h.db != nil {
		_ = h.db.Close()
		h.db = nil
	}
}

func (h *webAPI) handleOverview(w http.ResponseWriter, r *http.Request) {
	st, err := h.store()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	all, err := st.ListTunnels()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	running, s := webRunningSet()
	ov := map[string]any{
		"version":      version.Version,
		"commit":       version.Commit,
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
		"configPath":   h.cfg.Path,
		"dbPath":       h.cfg.App.DB,
		"logDir":       h.cfg.Log.Dir,
		"privileged":   hasPrivileges(),
		"running":      s != nil,
		"tunnelCount":  len(all),
		"enabledCount": countEnabled(all),
		"runningCount": len(running),
	}
	if s != nil {
		ov["mode"] = s.Mode
		ov["pid"] = s.Pid
		ov["startedAt"] = s.StartedAt.Format(time.RFC3339)
	}
	writeJSON(w, ov)
}

func countEnabled(list []*store.Tunnel) int {
	n := 0
	for _, t := range list {
		if t.Enabled {
			n++
		}
	}
	return n
}

/* --------------------------------- 隧道 --------------------------------- */

func (h *webAPI) handleTunnelsList(w http.ResponseWriter, r *http.Request) {
	st, err := h.store()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	all, err := st.ListTunnels()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_, s := webRunningSet()
	byUID, byName := runningInfo(s)
	out := make([]apiTunnel, 0, len(all))
	for _, t := range all {
		info, ok := byUID[t.UID]
		if !ok {
			info = byName[t.Name]
		}
		out = append(out, toAPITunnel(t, info.running, info.peerIP))
	}
	writeJSON(w, out)
}

// tunnelRun 是运行中隧道的一项状态。
type tunnelRun struct {
	running bool
	peerIP  string
}

// runningInfo 从运行状态中汇总各隧道的运行状态与对端 IP。
// 以 UID 索引为主（隧道改名后仍能对上号），名字索引作为旧状态文件的回退。
func runningInfo(s *daemon.State) (map[string]tunnelRun, map[string]tunnelRun) {
	byUID := map[string]tunnelRun{}
	byName := map[string]tunnelRun{}
	if s == nil {
		return byUID, byName
	}
	for _, t := range s.Tunnels {
		info := tunnelRun{running: true, peerIP: t.PeerIP}
		if t.UID != "" {
			byUID[t.UID] = info
		}
		byName[t.Name] = info
	}
	return byUID, byName
}

func (h *webAPI) handleTunnelGet(w http.ResponseWriter, r *http.Request) {
	t, err := h.getTunnel(r.PathValue("name"))
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	running, s := webRunningSet()
	byUID, byName := runningInfo(s)
	info, ok := byUID[t.UID]
	if !ok {
		info = byName[t.Name]
	}
	writeJSON(w, toAPITunnel(t, running[t.Name] || info.running, info.peerIP))
}

// tunnelWrite 是隧道的写入载荷。可清空的字段用指针表达：
// nil 表示「本次不改动」，显式传空串则表示清空（原实现无法清空已设置的私钥等字段）。
type tunnelWrite struct {
	// UID 是隧道稳定标识：带 UID 时更新该条隧道（名字可改）；不带则按名字新增。
	UID              string  `json:"uid"`
	Name             string  `json:"name"`
	Enabled          *bool   `json:"enabled"`
	SSHHost          string  `json:"sshHost"`
	SSHPort          int     `json:"sshPort"`
	SSHUser          string  `json:"sshUser"`
	SSHAuth          string  `json:"sshAuth"`
	Password         string  `json:"password"`
	SSHKeyFile       *string `json:"sshKeyFile"`
	SSHKeyPassphrase *string `json:"sshKeyPassphrase"`
	SSHHostKey       *string `json:"sshHostKey"`
	TunName          *string `json:"tunName"`
	TunAddress       *string `json:"tunAddress"`
	TunMTU           int     `json:"tunMtu"`
}

func (h *webAPI) handleTunnelUpsert(w http.ResponseWriter, r *http.Request) {
	var in tunnelWrite
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, errors.New("隧道名不能为空"))
		return
	}
	st, err := h.store()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	// 定位目标：带 UID → 更新该条隧道（允许改名）；否则按名字查找，没有则新建。
	var t *store.Tunnel
	if uid := strings.TrimSpace(in.UID); uid != "" {
		t, err = st.GetTunnelByUID(uid)
		if errors.Is(err, store.ErrNotExist) {
			writeErr(w, http.StatusNotFound, errors.New("隧道不存在（UID 已失效）"))
			return
		}
	} else {
		t, err = st.GetTunnel(name)
		if errors.Is(err, store.ErrNotExist) {
			// 名字不存在：视为新建
			t = &store.Tunnel{
				Name: name, Enabled: true,
				SSHPort: config.DefaultSSHPort, SSHUser: "root", SSHAuth: "key", SSHHostKey: "accept-new",
				TunName: config.DefaultTunName, TunAddress: config.DefaultTunAddress, TunMTU: config.DefaultTunMTU,
			}
			err = nil
		}
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// 改名：校验新名字未被占用。
	if t.Name != name {
		if other, oerr := st.GetTunnel(name); oerr == nil && other.UID != t.UID {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("隧道名 %q 已被占用", name))
			return
		}
		t.Name = name
	}

	// 连接地址（主机/端口）变化时，已保存的密码立即作废：
	// 密码是发给该地址的凭证，换了地址还沿用旧密码，等于把旧密码送到新地址。
	// 作废后隧道启动时会因缺少密码而失败，界面引导用户重新输入。
	newHost, newPort := t.SSHHost, t.SSHPort
	if v := strings.TrimSpace(in.SSHHost); v != "" {
		newHost = v
	}
	if in.SSHPort != 0 {
		newPort = in.SSHPort
	}
	addrChanged := newHost != t.SSHHost || newPort != t.SSHPort

	if v := strings.TrimSpace(in.SSHHost); v != "" {
		t.SSHHost = v
	}
	if in.SSHPort != 0 {
		t.SSHPort = in.SSHPort
	}
	if v := strings.TrimSpace(in.SSHUser); v != "" {
		t.SSHUser = v
	}
	if v := strings.TrimSpace(in.SSHAuth); v != "" {
		t.SSHAuth = v
	}
	if in.SSHKeyFile != nil {
		t.SSHKeyFile = strings.TrimSpace(*in.SSHKeyFile)
	}
	if in.SSHKeyPassphrase != nil {
		t.SSHKeyPassphrase = *in.SSHKeyPassphrase
	}
	if in.SSHHostKey != nil {
		t.SSHHostKey = strings.TrimSpace(*in.SSHHostKey)
	}
	if in.TunName != nil {
		t.TunName = strings.TrimSpace(*in.TunName)
	}
	if in.TunAddress != nil {
		t.TunAddress = strings.TrimSpace(*in.TunAddress)
	}
	if in.TunMTU != 0 {
		t.TunMTU = in.TunMTU
	}
	if in.Enabled != nil {
		t.Enabled = *in.Enabled
	}
	if addrChanged {
		// 地址变了：旧密码作废（本次若同时提交了新密码，则用新密码覆盖）。
		t.SSHPassword = ""
	}
	if in.Password != "" {
		enc, eerr := secret.Encrypt(in.Password)
		if eerr != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("加密密码失败: %w", eerr))
			return
		}
		t.SSHPassword = enc
	}
	if err := validateTunnelForStore(t); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := st.UpsertTunnel(t); err != nil {
		// 名字唯一约束冲突：改名为已存在的名字
		if strings.Contains(err.Error(), "UNIQUE") && strings.Contains(err.Error(), "name") {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("隧道名 %q 已被占用", name))
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, toAPITunnel(t, false, ""))
}

func (h *webAPI) handleTunnelDelete(w http.ResponseWriter, r *http.Request) {
	st, err := h.store()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	t, err := h.getTunnel(r.PathValue("name"))
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	if err := st.DeleteTunnel(t.Name); err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (h *webAPI) handleTunnelEnabled(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	st, err := h.store()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	t, err := h.getTunnel(r.PathValue("name"))
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	if err := st.SetEnabled(t.Name, in.Enabled); err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

/* -------------------------------- 路由 ---------------------------------- */

func (h *webAPI) handleRouteAdd(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cidr := strings.TrimSpace(r.URL.Query().Get("cidr"))
	bypass := parseBool(r.URL.Query().Get("bypass"))
	if cidr == "" {
		writeErr(w, http.StatusBadRequest, errors.New("缺少 cidr 参数"))
		return
	}
	if err := validateCIDROrIP(cidr); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	kind := store.RouteKindTunnel
	if bypass {
		kind = store.RouteKindBypass
	}
	err := h.mutateTunnel(name, func(t *store.Tunnel) error {
		for _, rt := range t.Routes {
			if rt.CIDR == cidr {
				return fmt.Errorf("路由 %s 已存在", cidr)
			}
		}
		t.Routes = append(t.Routes, store.Route{CIDR: cidr, Kind: kind})
		return nil
	})
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (h *webAPI) handleRouteDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cidr := strings.TrimSpace(r.URL.Query().Get("cidr"))
	if cidr == "" {
		writeErr(w, http.StatusBadRequest, errors.New("缺少 cidr 参数"))
		return
	}
	err := h.mutateTunnel(name, func(t *store.Tunnel) error {
		kept := t.Routes[:0]
		found := false
		for _, rt := range t.Routes {
			if rt.CIDR == cidr {
				found = true
				continue
			}
			kept = append(kept, rt)
		}
		if !found {
			return fmt.Errorf("路由 %s 不存在", cidr)
		}
		t.Routes = kept
		return nil
	})
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

/* -------------------------------- 转发 ---------------------------------- */

func (h *webAPI) handleForwardAdd(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var f apiForward
	if err := decodeJSON(r, &f); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if f.Direction != store.ForwardLocal && f.Direction != store.ForwardRemote {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("direction 仅支持 local|remote，当前: %q", f.Direction))
		return
	}
	if f.BindPort < 1 || f.BindPort > 65535 {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("bind_port 非法: %d", f.BindPort))
		return
	}
	if strings.TrimSpace(f.TargetHost) == "" || f.TargetPort < 1 || f.TargetPort > 65535 {
		writeErr(w, http.StatusBadRequest, errors.New("target_host/target_port 非法"))
		return
	}
	err := h.mutateTunnel(name, func(t *store.Tunnel) error {
		t.Forwards = append(t.Forwards, store.Forward{
			Direction: f.Direction, BindAddr: f.BindAddr, BindPort: f.BindPort,
			TargetHost: f.TargetHost, TargetPort: f.TargetPort, Enabled: f.Enabled,
		})
		return nil
	})
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (h *webAPI) handleForwardDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	dir := r.URL.Query().Get("direction")
	port, err := strconv.Atoi(r.URL.Query().Get("port"))
	if err != nil || port < 1 || port > 65535 {
		writeErr(w, http.StatusBadRequest, errors.New("port 参数非法"))
		return
	}
	err = h.mutateTunnel(name, func(t *store.Tunnel) error {
		kept := t.Forwards[:0]
		found := false
		for _, f := range t.Forwards {
			if f.Direction == dir && f.BindPort == port {
				found = true
				continue
			}
			kept = append(kept, f)
		}
		if !found {
			return fmt.Errorf("转发 %s:%d 不存在", dir, port)
		}
		t.Forwards = kept
		return nil
	})
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

/* ------------------------------- 动作/提权 ------------------------------- */

func (h *webAPI) handleAction(w http.ResponseWriter, r *http.Request) {
	op := r.PathValue("op")
	var in struct {
		Names []string `json:"names"`
	}
	_ = decodeJSON(r, &in) // 允许空 body

	// TUN 需要特权：本程序不做自动提权，直接告知前端需要管理员权限，由用户自行以管理员身份重启。
	if (op == "start" || op == "restart") && !hasPrivileges() {
		writeNeedAdmin(w, op, in.Names)
		return
	}

	var err error
	switch op {
	case "start":
		err = webStart(h.cfg, in.Names)
	case "stop":
		err = webStop(in.Names)
	case "restart":
		err = webRestart(h.cfg, in.Names)
	default:
		writeErr(w, http.StatusBadRequest, fmt.Errorf("未知操作: %s", op))
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// handleElevate 处理前端「以管理员身份重启」请求。
// 仅 GUI 托管模式可真正提权：记录待执行动作，由 sshtun-gui 轮询到后以管理员身份重启自身。
// 纯 web 模式不做任何提权，返回 409 指引用户自行以管理员权限重启程序。
func (h *webAPI) handleElevate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string   `json:"action"`
		Names  []string `json:"names"`
	}
	_ = decodeJSON(r, &in)
	if in.Action == "" {
		in.Action = "start"
	}

	if !h.managed {
		writeNeedAdmin(w, in.Action, in.Names)
		return
	}

	h.mu.Lock()
	h.pending = &elevateReq{Action: in.Action, Names: in.Names}
	h.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "elevating": true, "mode": "gui"})
}

// writeNeedAdmin 以 409 告知前端该操作需要管理员权限，并回带待执行动作以便用户提权后重试。
func writeNeedAdmin(w http.ResponseWriter, action string, names []string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        false,
		"error":     "启动/重启隧道需要管理员权限（创建 TUN 网卡并修改系统路由）",
		"needAdmin": true,
		"action":    action,
		"names":     names,
	})
}

/* --------------------------------- 退出 --------------------------------- */

// shutdownAuth 允许 GUI 托管实例（携带静态令牌）直接触发退出；其余情况要求已登录。
func (h *webAPI) shutdownAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.staticToken != "" {
			if !constantEqual(h.tokenFrom(r), h.staticToken) {
				writeErr(w, http.StatusUnauthorized, errors.New("无效的访问令牌"))
				return
			}
			next(w, r)
			return
		}
		if !h.needLogin || h.sessions.valid(h.tokenFrom(r)) {
			next(w, r)
			return
		}
		writeErr(w, http.StatusUnauthorized, errors.New("未登录或会话已过期"))
	}
}

// handleShutdown 优雅停止全部隧道（含路由清理）后退出进程，供 GUI 退出时调用。
// 先停隧道再退出：隧道会话收敛后运行循环会自行调用 ClearState。
func (h *webAPI) handleShutdown(w http.ResponseWriter, r *http.Request) {
	_ = webStop(nil)
	writeJSON(w, map[string]any{"ok": true})
	go func() {
		// 给响应写出与隧道收敛留出时间，随后退出进程。
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) {
			if s, _ := daemon.ActiveState(); s == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		_ = daemon.ClearState()
		os.Exit(0)
	}()
}

/* ------------------------------- 流量统计 ------------------------------- */

// handleStats 返回各运行隧道的累计流量与实时速率，以及汇总值。
// 统计源是各隧道 SSH 通道的应用层计数（见 stats.go）：本进程运行的隧道直接读计数器；
// 由其它进程（如后台运行实例）启动的隧道依据 state.json 中的累计字节与速率补全，
// 从而做到跨进程展示（无活跃实例时清空跨进程条目）。
func (h *webAPI) handleStats(w http.ResponseWriter, r *http.Request) {
	remote := make(map[string]trafficSample)
	if s, _ := daemon.ActiveState(); s != nil {
		for _, t := range s.Tunnels {
			remote[t.Name] = trafficSample{
				Up: t.Up, Down: t.Down,
				UpSpeed: t.UpSpeed, DownSpeed: t.DownSpeed,
			}
		}
	}
	traffic.sync(remote)
	samples := traffic.snapshot()
	var total trafficSample
	for _, s := range samples {
		total.Up += s.Up
		total.Down += s.Down
		total.UpSpeed += s.UpSpeed
		total.DownSpeed += s.DownSpeed
	}
	writeJSON(w, map[string]any{"tunnels": samples, "total": total})
}

/* --------------------------------- 日志 --------------------------------- */

func (h *webAPI) handleLogs(w http.ResponseWriter, r *http.Request) {
	lines := atoiDefault(r.URL.Query().Get("lines"), 300)
	if lines < 1 {
		lines = 1
	}
	if lines > 5000 {
		lines = 5000
	}
	tunnel := strings.TrimSpace(r.URL.Query().Get("tunnel"))
	dir := strings.TrimSpace(h.cfg.Log.Dir)
	if dir == "" {
		writeJSON(w, map[string]any{"path": "", "content": "", "note": "未配置日志目录（[log] dir 为空，日志输出到标准错误）"})
		return
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "sshtun-*.log"))
	if len(matches) == 0 {
		writeJSON(w, map[string]any{"path": "", "content": "", "note": "暂无日志文件"})
		return
	}
	latest := matches[0]
	for _, m := range matches[1:] {
		if m > latest {
			latest = m
		}
	}
	if tunnel != "" {
		// 逐行筛选出属于该隧道的日志（slog 文本处理器以 tunnel=<name> 记录该字段）。
		content, err := tailFileFiltered(latest, lines, func(line string) bool {
			return logLineTunnel(line) == tunnel
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if strings.TrimSpace(content) == "" {
			writeJSON(w, map[string]any{"path": latest, "content": "", "note": "隧道 " + tunnel + " 暂无日志"})
			return
		}
		writeJSON(w, map[string]any{"path": latest, "content": content, "tunnel": tunnel})
		return
	}
	content, err := tailFile(latest, lines)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"path": latest, "content": content})
}

// logLineTunnel 从一行 slog 文本日志中解析 tunnel 字段的值；无该字段返回空串。
// 兼容带引号（值含空格等特殊字符）与不带引号两种形式。
func logLineTunnel(line string) string {
	const key = "tunnel="
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(key):]
	if strings.HasPrefix(rest, `"`) {
		rest = rest[1:]
		if end := strings.IndexByte(rest, '"'); end >= 0 {
			return rest[:end]
		}
		return rest
	}
	if end := strings.IndexAny(rest, " \t"); end >= 0 {
		return rest[:end]
	}
	return rest
}

/* --------------------------------- 工具 --------------------------------- */

// handleFailures 返回各隧道最近一次启动失败的原因（kind=auth 表示凭据类失败，
// 前端据此弹出凭据修正窗口；启动成功后对应记录即被清除）。
func (h *webAPI) handleFailures(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, failureSnapshot())
}

/* --------------------------------- 设置 --------------------------------- */

// settingsPayload 是「设置」弹窗与后端之间的数据传输结构。
// WebPassword 只在用户输入新密码时非空（留空表示保持原值）；
// HasPassword 指示当前是否已设置访问密码（不回传密码明文）。
type settingsPayload struct {
	Path           string `json:"path"`
	DB             string `json:"db"`
	WebHostname    string `json:"webHostname"`
	WebPort        int    `json:"webPort"`
	WebCORS        string `json:"webCORS"`
	WebUsername    string `json:"webUsername"`
	WebPassword    string `json:"webPassword"`
	HasPassword    bool   `json:"hasPassword"`
	WebLanguage    string `json:"webLanguage"`
	WebTheme       string `json:"webTheme"`
	Tun2socks      string `json:"tun2socks"`
	ConnectTimeout int    `json:"connectTimeout"`
	Keepalive      int    `json:"keepalive"`
	LogLevel       string `json:"logLevel"`
	LogDir         string `json:"logDir"`
	LogConsole     string `json:"logConsole"`
}

// handleSettingsGet 返回当前基础配置（供设置弹窗回填）。
func (h *webAPI) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	c := h.cfg
	writeJSON(w, settingsPayload{
		Path:           c.Path,
		DB:             c.App.DB,
		WebHostname:    c.Web.Hostname,
		WebPort:        c.Web.Port,
		WebCORS:        c.Web.CORS,
		WebUsername:    c.Web.Username,
		HasPassword:    strings.TrimSpace(c.Web.Password) != "",
		WebLanguage:    c.Web.Language,
		WebTheme:       c.Web.Theme,
		Tun2socks:      c.Tun2socks.Path,
		ConnectTimeout: c.SSH.ConnectTimeout,
		Keepalive:      c.SSH.Keepalive,
		LogLevel:       c.Log.Level,
		LogDir:         c.Log.Dir,
		LogConsole:     c.Log.Console,
	})
}

// handleSettingsSave 保存设置到配置文件：仅更新基础配置，隧道数据仍保存在数据库中。
// 部分设置（Web 监听地址/端口、访问密码等）需要重启实例后生效，响应里会给出提示。
func (h *webAPI) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	var in settingsPayload
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	c := h.cfg
	next := *c // 值拷贝，避免校验失败时污染当前实例的配置
	next.App.DB = strings.TrimSpace(in.DB)
	next.Web.Hostname = strings.TrimSpace(in.WebHostname)
	next.Web.Port = in.WebPort
	next.Web.CORS = strings.TrimSpace(in.WebCORS)
	next.Web.Username = strings.TrimSpace(in.WebUsername)
	next.Web.Language = strings.TrimSpace(in.WebLanguage)
	next.Web.Theme = strings.TrimSpace(in.WebTheme)
	next.Tun2socks.Path = strings.TrimSpace(in.Tun2socks)
	next.SSH.ConnectTimeout = in.ConnectTimeout
	next.SSH.Keepalive = in.Keepalive
	next.Log.Level = strings.TrimSpace(in.LogLevel)
	next.Log.Dir = strings.TrimSpace(in.LogDir)
	next.Log.Console = strings.TrimSpace(in.LogConsole)

	// 密码：留空表示不修改；新密码加密后存储。
	if pw := strings.TrimSpace(in.WebPassword); pw != "" {
		enc, err := secret.Encrypt(pw)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("加密 Web 密码失败: %w", err))
			return
		}
		next.Web.Password = enc
	}

	if err := next.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if next.Web.Port < 0 || next.Web.Port > 65535 {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("[web] port 非法: %d", next.Web.Port))
		return
	}
	if next.SSH.ConnectTimeout <= 0 {
		writeErr(w, http.StatusBadRequest, errors.New("[ssh] connect_timeout 必须大于 0"))
		return
	}
	if next.SSH.Keepalive < 0 {
		writeErr(w, http.StatusBadRequest, errors.New("[ssh] keepalive 不能为负"))
		return
	}
	switch next.Log.Level {
	case "debug", "info", "warn", "error", "":
	default:
		writeErr(w, http.StatusBadRequest, fmt.Errorf("[log] level 非法: %q", next.Log.Level))
		return
	}
	if err := config.Save(c.Path, &next); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	// 落盘成功后同步内存配置：日志级别、SSH 参数等可即时生效。
	c.Log = next.Log
	c.SSH.ConnectTimeout = next.SSH.ConnectTimeout
	c.SSH.Keepalive = next.SSH.Keepalive
	c.Tun2socks.Path = next.Tun2socks.Path
	c.Web.Password = next.Web.Password
	// 界面语言与主题同样即时生效：同步后新连接的客户端立即拿到新值。
	c.Web.Language = next.Web.Language
	c.Web.Theme = next.Web.Theme

	writeJSON(w, map[string]any{
		"ok":      true,
		"restart": true,
		"note":    "设置已保存；界面语言与主题已立即生效，Web 监听地址/端口与访问密码需重启 sshtun 后生效",
	})
}

// getTunnel 按路径参数定位隧道：优先按稳定 UID，未命中再回退到名字（兼容旧客户端）。
func (h *webAPI) getTunnel(idOrName string) (*store.Tunnel, error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	if t, err := st.GetTunnelByUID(idOrName); err == nil {
		return t, nil
	}
	return st.GetTunnel(idOrName)
}

// mutateTunnel 载入隧道、应用变更并整体写回。
func (h *webAPI) mutateTunnel(idOrName string, mutate func(*store.Tunnel) error) error {
	st, err := h.store()
	if err != nil {
		return err
	}
	t, err := h.getTunnel(idOrName)
	if err != nil {
		return err
	}
	if err := mutate(t); err != nil {
		return err
	}
	return st.UpsertTunnel(t)
}

func validateTunnelForStore(t *store.Tunnel) error {
	if err := validateTunnelName(t.Name); err != nil {
		return err
	}
	if strings.TrimSpace(t.SSHHost) == "" {
		return errors.New("SSH 服务器地址不能为空")
	}
	if strings.TrimSpace(t.SSHUser) == "" {
		return errors.New("SSH 用户名不能为空")
	}
	if t.SSHPort < 1 || t.SSHPort > 65535 {
		return fmt.Errorf("SSH 端口非法: %d", t.SSHPort)
	}
	if t.SSHAuth != "password" && t.SSHAuth != "key" {
		return fmt.Errorf("认证方式仅支持 password/key，当前: %q", t.SSHAuth)
	}
	if t.SSHAuth == "key" && strings.TrimSpace(t.SSHKeyFile) == "" {
		return errors.New("认证方式为 key 时必须指定私钥文件")
	}
	if t.TunMTU != 0 && (t.TunMTU < 576 || t.TunMTU > 65535) {
		return fmt.Errorf("TUN MTU 非法: %d", t.TunMTU)
	}
	if strings.TrimSpace(t.TunAddress) != "" {
		if err := validateCIDROrIP(strings.TrimSpace(t.TunAddress)); err != nil {
			return fmt.Errorf("TUN 地址非法: %w", err)
		}
	}
	return nil
}

func tailFile(path string, n int) (string, error) {
	return tailFileFiltered(path, n, nil)
}

// tailFileFiltered 读取文件末尾片段并按 keep 过滤（keep 为 nil 表示不过滤），
// 再截取最后 n 行；过滤后不足 n 行时返回全部命中行。
func tailFileFiltered(path string, n int, keep func(string) bool) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	const maxRead = 256 * 1024
	off := int64(0)
	if fi, serr := f.Stat(); serr == nil && fi.Size() > maxRead {
		off = fi.Size() - maxRead
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return "", err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	// 从末尾按行截断到 maxRead 边界处可能产生半行，丢弃首个不完整行。
	if off > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	if keep != nil {
		kept := lines[:0]
		for _, ln := range lines {
			if keep(ln) {
				kept = append(kept, ln)
			}
		}
		lines = kept
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n"), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
}

func statusFor(err error) int {
	if errors.Is(err, store.ErrNotExist) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	// 只接受 application/json：浏览器跨站发出的「简单请求」只能是
	// text/plain 等类型，强制 JSON 可在免登录模式下阻断 CSRF。
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt := strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])
		if mt != "application/json" {
			return fmt.Errorf("仅支持 Content-Type: application/json，当前: %q", mt)
		}
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("解析请求体失败: %w", err)
	}
	return nil
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func parseBool(s string) bool {
	b, _ := strconv.ParseBool(strings.TrimSpace(s))
	return b
}
