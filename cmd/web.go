package cmd

// web：以本地 HTTP 服务承载隧道管理界面，用系统默认浏览器访问。
// `sshtun` 因此保持纯 CLI（不依赖 WebView2）；Windows 的独立 sshtun-gui 复用本文件导出的
// StartWebServer，仅额外用 WebView2 窗口展示。

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/store"
)

//go:embed all:webui
var webAssetsFS embed.FS

// WebOptions 是启动 Web 服务的参数；空值表示回退到配置文件 [web] 段或内置默认值。
type WebOptions struct {
	Hostname string // 监听地址
	Port     int    // 监听端口；0 由内核分配
	CORS     string // 逗号分隔的允许源列表，* 表示任意源
	Username string // 登录用户名
	Password string // 登录密码
	// Token 是 GUI 托管实例专用的随机访问令牌：设置后所有 API 请求都必须携带它。
	// 用于避免「管理员权限 + 回环免登录」时被本机其它进程或网页任意操控。
	Token   string
	Managed bool // 由 sshtun-gui 拉起；需要管理员权限时交由 GUI 自我提权重启
}

// WebServer 是已启动的 Web 服务句柄。
type WebServer struct {
	URL  string // 可用于浏览器访问的地址
	Addr string // 实际监听地址（host:port）
	srv  *http.Server
	ln   net.Listener
	api  *webAPI
}

var (
	webNoWindow bool
	webHostname string
	webPort     int
	webCORS     string
	webUsername string
	webPassword string
	// webManaged 表示本实例由 sshtun-gui 拉起，提权交由 GUI 处理（web 模式自身不做任何提权）。
	webManaged bool
	// webToken 是 GUI 托管实例的随机访问令牌（内部参数）。
	webToken string
	// 以下为 GUI 提权重启后透传的隐藏参数：新实例就绪后自动续跑被权限拦截的动作。
	webElevatedAction string
	webElevatedNames  string
)

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Start the built-in web management UI (open it in the default browser to manage the tunnels)",
	RunE:  runWeb,
}

func init() {
	f := webCmd.Flags()
	f.StringVar(&webHostname, "hostname", "", "listen address (defaults to [web] hostname in the config, otherwise 127.0.0.1)")
	f.IntVar(&webPort, "port", 0, "listen port (defaults to [web] port in the config, otherwise 8080; 0 means auto-assign)")
	f.StringVar(&webCORS, "cors", "", "allowed cross-origin sources, comma separated; * allows any (defaults to [web] cors in the config)")
	f.StringVar(&webUsername, "username", "", "login user name (defaults to [web] username in the config, otherwise admin)")
	f.StringVar(&webPassword, "password", "", "login password (defaults to [web] password in the config; empty means no login when bound to loopback)")
	f.BoolVar(&webNoWindow, "no-window", false, "only start the local service, do not open a browser (for debugging)")
	f.BoolVar(&webManaged, "_managed", false, "(internal) launched by sshtun-gui, the elevation is handled by the GUI")
	f.StringVar(&webToken, "_token", "", "(internal) random access token of the GUI managed instance")
	f.StringVar(&webElevatedAction, "_action", "", "(internal) the action to run automatically after elevating")
	f.StringVar(&webElevatedNames, "_names", "", "(internal) the target tunnels of the action to run after elevating")
	for _, n := range []string{"_managed", "_token", "_action", "_names"} {
		_ = f.MarkHidden(n)
	}
	rootCmd.AddCommand(webCmd)
}

// runWeb 是 web 子命令入口。root 的 PersistentPreRunE 对 web 已跳过，
// 因此这里自行加载配置并确保数据库就绪。
func runWeb(cmd *cobra.Command, args []string) error {
	cfg, err := configLoad()
	if err != nil {
		return err
	}
	if st, oerr := store.Open(cfg.App.DB); oerr != nil {
		return oerr
	} else {
		_ = st.Close()
	}

	srv, err := StartWebServer(cfg, WebOptions{
		Hostname: webHostname,
		Port:     webPort,
		CORS:     webCORS,
		Username: webUsername,
		Password: webPassword,
		Token:    webToken,
		Managed:  webManaged,
	})
	if err != nil {
		return err
	}

	// 提权重启后自动续跑此前被权限拦截的动作。
	if action := strings.TrimSpace(webElevatedAction); action != "" {
		names := SplitCSV(webElevatedNames)
		go func() {
			time.Sleep(700 * time.Millisecond)
			runPendingAction(cfg, action, names)
		}()
	}

	if webNoWindow {
		fmt.Printf("sshtun web service started: %s\n", srv.URL)
		WaitSignal()
		srv.Shutdown()
		stopOwnedDaemon()
		return nil
	}

	if err := openBrowserDefault(srv.URL); err != nil {
		fmt.Fprintf(os.Stderr, "cannot open the browser automatically: %v\n", err)
	}
	fmt.Printf("sshtun web service started: %s\npress Ctrl+C to exit\n", srv.URL)
	WaitSignal()
	srv.Shutdown()
	// 本进程派生的后台实例由本进程收尾（隧道随 Web 退出而停止）。
	stopOwnedDaemon()
	return nil
}

// StartWebServer 按 opts、配置文件 [web] 段与内置默认值的优先级启动本地服务。
// 返回的 WebServer.URL 可直接用于浏览器访问。
func StartWebServer(cfg *config.Config, opt WebOptions) (*WebServer, error) {
	hostname := firstNonEmpty(opt.Hostname, cfg.Web.Hostname, config.DefaultWebHostname)
	port := firstNonZero(opt.Port, cfg.Web.Port, config.DefaultWebPort)
	cors := firstNonEmpty(opt.CORS, cfg.Web.CORS)
	username := firstNonEmpty(opt.Username, cfg.Web.Username, config.DefaultWebUsername)
	password := firstNonEmpty(opt.Password, cfg.Web.Password)

	loopback := isLoopbackHost(hostname)
	needLogin := password != ""
	if !needLogin && !loopback {
		return nil, fmt.Errorf("a web access password is required when binding to a non-loopback address %s: set [web] password in the config, or pass --password", hostname)
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(hostname, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s:%d: %w", hostname, port, err)
	}

	api := &webAPI{
		cfg:         cfg,
		sessions:    newSessionStore(webSessionTTL),
		username:    username,
		password:    password,
		needLogin:   needLogin,
		staticToken: strings.TrimSpace(opt.Token),
		managed:     opt.Managed,
	}

	mux := http.NewServeMux()
	api.register(mux)

	sub, err := fs.Sub(webAssetsFS, "webui")
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	// 静态资源禁用缓存：程序升级后浏览器/GUI 立即加载最新界面，
	// 避免继续使用旧版 CSS/JS（嵌入式资源没有 Last-Modified，浏览器易长期缓存）。
	mux.Handle("/", noCache(http.FileServer(http.FS(sub))))

	srv := &http.Server{
		Handler:           localGuard(hostname, cors, mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	go func() { _ = srv.Serve(ln) }()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	dispHost := hostname
	if dispHost == "0.0.0.0" || dispHost == "::" || dispHost == "" || dispHost == "localhost" {
		dispHost = "127.0.0.1"
	}
	return &WebServer{
		URL:  fmt.Sprintf("http://%s", net.JoinHostPort(dispHost, portStr)),
		Addr: ln.Addr().String(),
		srv:  srv,
		ln:   ln,
		api:  api,
	}, nil
}

// Shutdown 优雅关闭服务。
func (s *WebServer) Shutdown() {
	if s == nil || s.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(ctx)
	if s.api != nil {
		s.api.CloseStore()
	}
}

// SplitCSV 把逗号分隔串解析为去空的切片。
func SplitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// WaitSignal 阻塞直到收到中断/终止信号。
func WaitSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	signal.Stop(ch)
}

// noCache 为响应加上禁用缓存的头（静态资源每次都取最新）。
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// localGuard 做两类防护，再交给 CORS 与业务处理器：
//  1. Host 校验：绑定回环地址时只接受 127.0.0.1 / ::1 / localhost 的 Host 头，
//     阻断 DNS rebinding（攻击者域名解析到 127.0.0.1 后以同源身份读写）。
//  2. Origin 校验：跨站请求（Origin 与 Host 不一致）一律拒绝，除非该源已被
//     [web] cors 显式允许；这阻断了「免登录模式下任意网页静默改配置」的 CSRF。
func localGuard(hostname, cors string, next http.Handler) http.Handler {
	allowed := SplitCSV(cors)
	allowAll := false
	set := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		if o == "*" {
			allowAll = true
		}
		set[o] = true
	}
	loopback := isLoopbackHost(hostname)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loopback && !isLoopbackHost(stripPort(r.Host)) {
			writeErr(w, http.StatusForbidden, fmt.Errorf("拒绝非回环 Host: %q", r.Host))
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			if !sameHost(origin, r.Host) && !allowAll && !set[origin] {
				writeErr(w, http.StatusForbidden, errors.New("拒绝跨站请求"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
	return corsMiddleware(cors, h)
}

// stripPort 去掉 Host 头中的端口，兼容 IPv6 字面量 [::1]:8080。
func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.Trim(host, "[]")
}

// sameHost 判断 Origin 与 Host 是否指向同一主机:端口。
func sameHost(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

// corsMiddleware 按逗号分隔的允许源列表处理 CORS：命中则回显 Origin 并放行预检，
// 列表为空时不发送任何 CORS 头（仅同源）。"*" 表示允许任意源，此时不能携带凭证
// （浏览器规范禁止 * 与 Allow-Credentials 同时使用）。
func corsMiddleware(cors string, next http.Handler) http.Handler {
	allowed := SplitCSV(cors)
	if len(allowed) == 0 {
		return next
	}
	allowAll := false
	set := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		if o == "*" {
			allowAll = true
		}
		set[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			h := w.Header()
			switch {
			case allowAll:
				h.Set("Access-Control-Allow-Origin", "*")
			case set[origin]:
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Add("Vary", "Origin")
			}
			if h.Get("Access-Control-Allow-Origin") != "" {
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Content-Type, X-Token")
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopbackHost(h string) bool {
	if h == "" || strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstNonZero(vals ...int) int {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}
