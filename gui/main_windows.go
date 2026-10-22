//go:build windows

// sshtun-gui：Windows 图形界面，本质是一个极薄的 WebView2 外壳。
// 它不内嵌 sshtun 的实现，而是直接拉起同目录下的 `sshtun web` 子进程，
// 再用系统内置的 Edge WebView2 内核把该本地 Web 界面渲染成窗口（纯 Go，无 CGO）。
// 关闭窗口(X) 不退出程序，而是最小化到系统托盘；托盘双击还原窗口，右键可退出。
// 强制以管理员身份运行：非管理员启动时请求 UAC 重启自身。
// 启动时检查是否已有实例：已有则把它的窗口唤到前台并退出，未运行才打开新窗口。
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

const (
	winTitle  = "sshtun · 隧道管理器"
	winWidth  = 920
	winHeight = 700
	// minWinWidth/minWinHeight 是窗口可缩到的最小尺寸，取常见手机竖屏尺寸；
	// Web 界面已适配窄屏，缩到该尺寸仍可正常使用。
	minWinWidth  = 380
	minWinHeight = 540

	// createNoWindow 让子进程不弹出控制台窗口。
	createNoWindow = 0x08000000

	// swShow 是 ShellExecute 的窗口显示方式（SW_SHOWNORMAL）。
	swShow = 5

	// singletonMutexName 是单实例互斥体（Local 作用域，限当前登录会话）。
	singletonMutexName = "Local\\sshtun-gui-instance"

	// DPI 感知相关：无清单的进程默认知为 DPI 不感知，高分辨率屏上整个界面会被系统
	// 位图拉伸，导致字体模糊。这里主动声明按显示器 DPI 渲染。
	dpiAwarenessPerMonitorV2  = ^uintptr(3) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2（即 -4）
	processPerMonitorDpiAware = 2           // PROCESS_PER_MONITOR_DPI_AWARE（shcore）
)

// Win32 常量与消息号。
const (
	wmClose     = 0x0010
	wmNull      = 0x0000
	wmSetIcon   = 0x0080
	wmLButtonUp = 0x0202
	wmLBtnDbl   = 0x0203
	wmRButtonUp = 0x0205

	iconSmall = 0
	iconBig   = 1

	imageIcon     = 1
	lrDefaultSize = 0x0040
	lrShared      = 0x8000
	swHide        = 0
	swRestore     = 9

	// 托盘图标回调消息与通知常量。
	trayCallbackMsg = 0x8000 + 1 // WM_APP + 1
	nimAdd          = 0
	nimDelete       = 2
	nifMessage      = 0x00000001
	nifIcon         = 0x00000002
	nifTip          = 0x00000004

	mfString       = 0x00000000
	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100
	trayMenuQuitID = 1

	mbOK        = 0x00000000
	mbIconError = 0x00000010

	// gwlpWndProc 是 SetWindowLongPtr 取窗口过程地址的索引（GWLP_WNDPROC = -4）。
	gwlpWndProc = ^uintptr(3)
)

type point struct {
	X int32
	Y int32
}

// rect 对应 Win32 的 RECT（客户区或窗口矩形）。
type rect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

// notifyIconDataW 对应 Win32 的 NOTIFYICONDATAW（Vista+，x64 下大小为 976 字节）。
type notifyIconDataW struct {
	CbSize           uint32
	Hwnd             windows.Handle
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     windows.Handle
}

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	shcore   = windows.NewLazySystemDLL("shcore.dll")

	procLoadImage        = user32.NewProc("LoadImageW")
	procSendMessage      = user32.NewProc("SendMessageW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procSetForegroundWin = user32.NewProc("SetForegroundWindow")
	procSetWindowLongPtr = user32.NewProc("SetWindowLongPtrW")
	procCallWindowProc   = user32.NewProc("CallWindowProcW")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenuW      = user32.NewProc("AppendMenuW")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procPostMessage      = user32.NewProc("PostMessageW")
	procMessageBox       = user32.NewProc("MessageBoxW")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	procFindWindow       = user32.NewProc("FindWindowW")
	procShellNotifyIcon  = shell32.NewProc("Shell_NotifyIconW")
	procGetWindowRect    = user32.NewProc("GetWindowRect")
	procGetClientRect    = user32.NewProc("GetClientRect")

	// DPI 相关（按需查找，缺失时以 .Find() 判定并回退到旧接口）。
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	procSetProcessDPIAware            = user32.NewProc("SetProcessDPIAware")
	procGetDpiForSystem               = user32.NewProc("GetDpiForSystem")
	procSetProcessDpiAwareness        = shcore.NewProc("SetProcessDpiAwareness")
)

var (
	configPath string
	sshtunPath string
	noWindow   bool
	// backendToken 是本进程与后端之间的一次性访问令牌。
	// 后端以管理员权限运行，若无令牌则本机任意进程/网页都能操控它，故必须启用。
	backendToken string
	// 由提权重启的上一实例透传：新实例就绪后自动续跑此前被权限拦截的动作。
	elevatedAction string
	elevatedNames  string
	// elevatedRelaunch 标记本进程由提权重启产生：仍要持有单实例句柄以免被后续启动抢占，
	// 但不因「已有实例」而退出（提权瞬间新旧实例会短暂并存）。
	elevatedRelaunch bool
)

// 窗口/托盘运行时状态。
var (
	backendRef *backend
	// backendURL 是后端的本地访问地址，供退出时请求其优雅停止隧道。
	backendURL string
	prevProc   uintptr
	trayHwnd   windows.Handle
	trayAdded  bool
	quitting   int32
	// singletonMutex 持有单实例互斥体句柄，生命周期随进程（退出时由系统回收）。
	singletonMutex windows.Handle
)

func main() {
	// 必须在创建任何窗口前声明 DPI 感知，否则高分辨率屏上界面会被系统拉伸而模糊。
	enableDpiAwareness()

	// GUI 程序本就被双击运行，禁止 cobra 的 mousetrap 提示（命令行工具/请在 cmd.exe 中运行）。
	cobra.MousetrapHelpText = ""

	root := &cobra.Command{
		Use:           "sshtun-gui",
		Short:         "sshtun 隧道管理器（Windows 图形界面）",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          run,
	}
	f := root.PersistentFlags()
	f.StringVarP(&configPath, "config", "c", "", "配置文件路径（透传给 sshtun，留空用 sshtun 默认）")
	f.StringVar(&sshtunPath, "sshtun", "", "sshtun 可执行文件路径（默认：同目录 sshtun.exe 或 PATH）")
	f.BoolVar(&noWindow, "no-window", false, "仅启动后端服务、不打开窗口（调试用）")
	f.StringVar(&backendToken, "_token", "", "（内部）GUI 与后端之间的访问令牌")
	f.StringVar(&elevatedAction, "_action", "", "（内部）提权重启后自动执行的动作")
	f.StringVar(&elevatedNames, "_names", "", "（内部）提权重启后自动执行的目标隧道")
	f.BoolVar(&elevatedRelaunch, "_elevated", false, "（内部）由提权重启产生的新实例")
	for _, n := range []string{"_token", "_action", "_names", "_elevated"} {
		_ = f.MarkHidden(n)
	}

	if err := root.Execute(); err != nil {
		showFatal(err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// 单实例：已有实例则把它的窗口唤到前台后退出，未运行才继续开新窗口。
	// --no-window 为调试用途，不参与限制。
	if !noWindow {
		if acquireSingleton() && !elevatedRelaunch {
			focusExisting()
			return nil
		}
		// 强制以管理员身份运行：非管理员实例立即请求 UAC 重启自身，由提权后的新实例开界面。
		// 提权重启产生的新实例（--_elevated）已是管理员，跳过此步以免反复弹 UAC。
		if !elevatedRelaunch && !isElevated() {
			if err := relaunchElevated("", nil); err != nil {
				return fmt.Errorf("sshtun-gui 需要以管理员身份运行: %w", err)
			}
			return nil
		}
	}

	exe, err := findSSHStun()
	if err != nil {
		return err
	}

	port, err := freePort()
	if err != nil {
		return err
	}
	tok, err := newBackendToken()
	if err != nil {
		return fmt.Errorf("生成访问令牌失败: %w", err)
	}
	if backendToken == "" {
		backendToken = tok
	}
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	backendURL = url

	logs := &tailBuffer{max: 8192}
	b, err := startBackend(exe, port, logs)
	if err != nil {
		return err
	}
	defer b.kill()

	if err := waitReady(url, b, logs, 15*time.Second); err != nil {
		return err
	}

	// 监听后端的提权请求：界面里点「以管理员身份重启」后，以管理员身份重启本程序。
	go watchElevation(url, b)

	if noWindow {
		fmt.Printf("sshtun-gui 后端已启动: %s\n按 Ctrl+C 退出\n", url)
		waitSignal()
		return nil
	}
	return runWindow(url, b)
}

// newBackendToken 生成用于 GUI ↔ 后端鉴权的随机令牌（32 字节十六进制）。
func newBackendToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

/* --------------------------- 后端子进程（sshtun web） --------------------------- */

// backend 是被拉起的 `sshtun web` 子进程。
type backend struct {
	cmd  *exec.Cmd
	done chan struct{}
}

// findSSHStun 定位 sshtun 可执行文件：显式路径 > 自身同目录 > PATH。
func findSSHStun() (string, error) {
	if sshtunPath != "" {
		if p, err := filepath.Abs(sshtunPath); err == nil {
			return p, nil
		}
		return sshtunPath, nil
	}
	if self, err := os.Executable(); err == nil {
		dir := filepath.Dir(self)
		for _, n := range []string{"sshtun.exe", "sshtun"} {
			p := filepath.Join(dir, n)
			if fi, e := os.Stat(p); e == nil && !fi.IsDir() {
				return p, nil
			}
		}
	}
	for _, n := range []string{"sshtun.exe", "sshtun"} {
		if p, e := exec.LookPath(n); e == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("未找到 sshtun 可执行文件：请将 sshtun-gui.exe 与 sshtun.exe 放在同一目录，或用 --sshtun 指定路径")
}

// freePort 向内核申请一个空闲的回环端口号（立即释放后交给后端绑定）。
func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("选择本地端口失败: %w", err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// startBackend 以 `sshtun web --no-window --_managed` 拉起后端，并把输出汇入 logs。
// 提权由 GUI 自身负责，后端只回报 needAdmin，因此这里透传 _managed 与待续跑动作。
func startBackend(exe string, port int, logs *tailBuffer) (*backend, error) {
	args := []string{"web", "--no-window", "--hostname", "127.0.0.1", "--port", strconv.Itoa(port), "--_managed=true"}
	if backendToken != "" {
		args = append(args, "--_token="+backendToken)
	}
	if elevatedAction != "" {
		args = append(args, "--_action="+elevatedAction)
	}
	if elevatedNames != "" {
		args = append(args, "--_names="+elevatedNames)
	}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	c := exec.Command(exe, args...)
	c.Dir = filepath.Dir(exe)
	c.Stdout = logs
	c.Stderr = logs
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}

	if err := c.Start(); err != nil {
		return nil, fmt.Errorf("启动 sshtun 失败: %w", err)
	}
	// 把后端并入本进程的任务对象：GUI 异常退出时由系统连带结束它，避免进程残留。
	guardBackend(c)
	b := &backend{cmd: c, done: make(chan struct{})}
	go func() {
		_ = c.Wait()
		close(b.done)
	}()
	return b, nil
}

// exited 报告子进程是否已退出。
func (b *backend) exited() bool {
	select {
	case <-b.done:
		return true
	default:
		return false
	}
}

// kill 终止子进程（幂等）。
func (b *backend) kill() {
	if b == nil || b.cmd == nil || b.cmd.Process == nil {
		return
	}
	_ = b.cmd.Process.Kill()
}

// shutdown 请求后端优雅停止全部隧道并清理路由，随后退出子进程；
// 在 timeout 内退出则返回 true，超时返回 false（由调用方强杀兜底）。
// 走一次优雅清理可避免强制终止时残留的路由与状态文件。
func (b *backend) shutdown(url string, timeout time.Duration) bool {
	if b == nil || url == "" || b.exited() {
		return false
	}
	req, err := http.NewRequest(http.MethodPost, url+"/api/shutdown", nil)
	if err != nil {
		return false
	}
	if backendToken != "" {
		req.Header.Set("X-Token", backendToken)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if b.exited() {
			return true
		}
		time.Sleep(120 * time.Millisecond)
	}
	return false
}

// waitReady 轮询后端 /api/session，直到可用或子进程提前退出/超时。
func waitReady(url string, b *backend, logs *tailBuffer, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 700 * time.Millisecond}
	for time.Now().Before(deadline) {
		if b.exited() {
			return fmt.Errorf("sshtun 后端启动失败（进程已退出）\n%s", logs.String())
		}
		resp, err := apiGet(client, url+"/api/session")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(120 * time.Millisecond)
	}
	return fmt.Errorf("等待 sshtun 后端就绪超时\n%s", logs.String())
}

// apiGet 带访问令牌发起 GET，供 GUI 轮询受保护端点使用。
func apiGet(client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if backendToken != "" {
		req.Header.Set("X-Token", backendToken)
	}
	return client.Do(req)
}

// tailBuffer 是保留末尾 max 字节的并发安全缓冲，用于收集子进程输出。
type tailBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf.Write(p)
	if t.max > 0 && t.buf.Len() > t.max {
		b := t.buf.Bytes()
		keep := b[t.buf.Len()-t.max:]
		t.buf.Reset()
		t.buf.Write(keep)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.buf.String()
}

/* --------------------------- 子进程兜底清理（任务对象） --------------------------- */

var (
	backendJobOnce sync.Once
	backendJobObj  windows.Handle
)

// backendJob 返回带「关闭即终止成员」策略的任务对象句柄（只创建一次）。
// GUI 一旦退出（含崩溃/被强杀），系统会关闭该句柄并连带结束 sshtun 后端子进程，
// 后端再借自身的任务对象结束 tun2socks，避免整条进程链残留。
func backendJob() windows.Handle {
	backendJobOnce.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
			BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
				LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			},
		}
		if _, err := windows.SetInformationJobObject(h,
			windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			_ = windows.CloseHandle(h)
			return
		}
		backendJobObj = h
	})
	return backendJobObj
}

// guardBackend 把后端子进程纳入任务对象。失败不影响运行，仅失去兜底清理。
func guardBackend(c *exec.Cmd) {
	job := backendJob()
	if job == 0 || c == nil || c.Process == nil {
		return
	}
	h, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(c.Process.Pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	_ = windows.AssignProcessToJobObject(job, h)
}

/* --------------------------------- 窗口 --------------------------------- */

// runWindow 打开 WebView2 窗口展示界面并进入消息循环，直到用户从托盘退出。
func runWindow(url string, b *backend) error {
	// Win32 消息循环要求窗口创建与消息泵在同一 OS 线程上，锁定主协程线程。
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	backendRef = b
	hideConsole()

	icon := loadAppIcon()
	// 按显示器 DPI 换算物理像素，使窗口在任意缩放下保持一致的观感大小。
	wpx, hpx := scaledPx(winWidth), scaledPx(winHeight)
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  webviewDataPath(),
		WindowOptions: webview2.WindowOptions{
			Title:  winTitle,
			Width:  uint(wpx),
			Height: uint(hpx),
			Center: true,
			IconId: 1, // 由 gui/rsrc_windows_amd64.syso 嵌入的图标资源
		},
	})
	if w == nil {
		return fmt.Errorf("WebView2 初始化失败：请确认已安装 Microsoft Edge WebView2 运行时（Windows 10/11 通常已内置）")
	}
	defer w.Destroy()

	hwnd := windows.Handle(uintptr(w.Window()))
	setWindowIcon(hwnd, icon)
	subclassWindow(hwnd)    // 拦截 WM_CLOSE，改为最小化到托盘
	addTrayIcon(hwnd, icon) // 托盘图标 + 右键退出
	defer removeTrayIcon()

	// 初始尺寸（HintNone：只设大小，不改最小/最大限制）。
	w.SetSize(wpx, hpx, webview2.HintNone)

	// 最小尺寸：交给 webview2 的 HintMin —— 它把尺寸记在 WM_GETMINMAXINFO
	// 的上报值里，系统拖到边界即停，不会与鼠标互相拉扯，也不会像旧方案那样
	// 在 WM_SIZE 里调 SetWindowPos 把窗口甩到屏幕左上角。
	// 不设上限，窗口可自由放大到屏幕大小。
	//
	// 最小客户区按初始客户区等比换算（同一 DPI 基准，不会再查一次 DPI）。
	minCW := wpx * minWinWidth / winWidth
	minCH := hpx * minWinHeight / winHeight
	mw, mh := minTrackSize(uintptr(hwnd), minCW, minCH)
	if mw > 0 && mh > 0 {
		w.SetSize(mw, mh, webview2.HintMin)
	}

	w.Navigate(navURL(url, backendToken))
	w.Run() // 阻塞至窗口真正销毁（退出）
	b.kill()
	return nil
}

// navURL 把访问令牌作为一次性查询参数拼到入口地址上；
// 页面内的 JS 会在首次加载时读取它、写入 sessionStorage，并立即从地址栏清除，
// 使后续请求通过 X-Token 头携带令牌（后端不接受查询参数作为长期凭证）。
func navURL(base, token string) string {
	if token == "" {
		return base
	}
	return base + "/?t=" + token
}

// subclassWindow 替换窗口过程，返回的原过程存入 prevProc 以便转发未处理消息。
func subclassWindow(hwnd windows.Handle) {
	prevProc, _, _ = procSetWindowLongPtr.Call(uintptr(hwnd), gwlpWndProc, windows.NewCallback(trayWndProc))
}

// trayWndProc 是子类化的窗口过程：关闭走托盘；托盘消息处理双击还原与右键菜单。
func trayWndProc(hwnd, msg, wp, lp uintptr) uintptr {
	switch msg {
	case wmClose:
		if atomic.LoadInt32(&quitting) == 0 {
			// 关闭按钮：隐藏窗口（保留托盘图标），不退出进程。
			_, _, _ = procShowWindow.Call(hwnd, swHide)
			return 0
		}
	case trayCallbackMsg:
		switch lp & 0xFFFF {
		case wmLButtonUp, wmLBtnDbl:
			_, _, _ = procShowWindow.Call(hwnd, swRestore)
			_, _, _ = procSetForegroundWin.Call(hwnd)
			return 0
		case wmRButtonUp:
			showTrayMenu(hwnd)
			return 0
		}
	}
	return callWindowProc(prevProc, hwnd, msg, wp, lp)
}

// minTrackSize 计算「整窗」最小尺寸（含标题栏与边框），供 webview2 的 HintMin 使用。
//
// cw/ch 是最小客户区（由调用方按初始客户区等比换算得出，避免二次查询 DPI
// 得到不同基准）。边框宽度直接从实际窗口量出（窗口矩形 − 客户区矩形）：
// 窗口坐标单位与 GetDpiForSystem 的换算关系在不同 DPI 设置下并不稳定，
// 用实测差值最可靠。
func minTrackSize(hwnd uintptr, cw, ch int) (int, int) {
	var wr, cr rect
	if r, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&wr))); r == 0 {
		return cw, ch
	}
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&cr)))
	frameW := int(wr.Right-wr.Left) - int(cr.Right)
	frameH := int(wr.Bottom-wr.Top) - int(cr.Bottom)
	if frameW < 0 {
		frameW = 0
	}
	if frameH < 0 {
		frameH = 0
	}
	return cw + frameW, ch + frameH
}

// callWindowProc 转发未处理的消息给原窗口过程。
func callWindowProc(proc, hwnd, msg, wp, lp uintptr) uintptr {
	if proc == 0 {
		return 0
	}
	r, _, _ := procCallWindowProc.Call(proc, hwnd, msg, wp, lp)
	return r
}

// showTrayMenu 在光标处弹出托盘右键菜单。
func showTrayMenu(hwnd uintptr) {
	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer func() { _, _, _ = procDestroyMenu.Call(hMenu) }()

	label, _ := windows.UTF16PtrFromString("退出")
	_, _, _ = procAppendMenuW.Call(hMenu, mfString, trayMenuQuitID, uintptr(unsafe.Pointer(label)))

	var pt point
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// 先置前，菜单才会在点击别处时正常消失。
	_, _, _ = procSetForegroundWin.Call(hwnd)
	cmd, _, _ := procTrackPopupMenu.Call(hMenu,
		tpmRightButton|tpmReturnCmd,
		uintptr(int(pt.X)), uintptr(int(pt.Y)), 0, hwnd, 0)
	_, _, _ = procPostMessage.Call(hwnd, wmNull, 0, 0)

	if cmd == trayMenuQuitID {
		quitApp(hwnd)
	}
}

// quitApp 执行真正退出：删托盘图标、优雅结束后端（停隧道、清路由）、恢复窗口过程并关闭窗口。
func quitApp(hwnd uintptr) {
	atomic.StoreInt32(&quitting, 1)
	removeTrayIcon()
	if backendRef != nil {
		// 先请求后端优雅停止全部隧道并清理路由，再兜底强杀（幂等）。
		backendRef.shutdown(backendURL, 8*time.Second)
		backendRef.kill()
	}
	// 恢复原始窗口过程，使随后的 WM_CLOSE 真正销毁窗口并结束消息循环。
	if prevProc != 0 {
		_, _, _ = procSetWindowLongPtr.Call(hwnd, gwlpWndProc, prevProc)
	}
	_, _, _ = procPostMessage.Call(hwnd, wmClose, 0, 0)
}

/* --------------------------------- 托盘 --------------------------------- */

// loadAppIcon 从本程序嵌入的图标组资源加载共享图标句柄。
// rsrc 生成 .syso 时按「先清单、后图标」的顺序分配资源 ID：无清单时图标组为 1，
// 有清单时清单占用 1、图标组顺延为 2。因此这里在小区间内逐个尝试，
// 取第一个能按 IMAGE_ICON 加载成功的 ID，避免把 ID 写死而受清单有无影响。
func loadAppIcon() uintptr {
	var h windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &h); err != nil {
		return 0
	}
	for id := uintptr(1); id <= 8; id++ {
		icon, _, _ := procLoadImage.Call(
			uintptr(h), id, imageIcon, 0, 0, lrDefaultSize|lrShared)
		if icon != 0 {
			return icon
		}
	}
	return 0
}

func setWindowIcon(hwnd windows.Handle, icon uintptr) {
	if icon == 0 {
		return
	}
	_, _, _ = procSendMessage.Call(uintptr(hwnd), wmSetIcon, iconSmall, icon)
	_, _, _ = procSendMessage.Call(uintptr(hwnd), wmSetIcon, iconBig, icon)
}

func addTrayIcon(hwnd windows.Handle, icon uintptr) {
	var nid notifyIconDataW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.Hwnd = hwnd
	nid.UID = 1
	nid.UFlags = nifMessage | nifIcon | nifTip
	nid.UCallbackMessage = trayCallbackMsg
	nid.HIcon = windows.Handle(icon)
	if tip, err := windows.UTF16FromString(winTitle); err == nil {
		copy(nid.SzTip[:], tip)
	}
	if r, _, _ := procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&nid))); r != 0 {
		trayAdded = true
		trayHwnd = hwnd
	}
}

func removeTrayIcon() {
	if !trayAdded {
		return
	}
	var nid notifyIconDataW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.Hwnd = trayHwnd
	nid.UID = 1
	_, _, _ = procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
	trayAdded = false
}

/* --------------------------------- 杂项 --------------------------------- */

// webviewDataPath 返回 WebView2 的缓存目录。
// 管理员实例与非管理员实例各用一份：提权重启时新旧实例会短暂并存，
// 共用同一目录会因占用导致新实例初始化失败。
func webviewDataPath() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	mode := "user"
	if isElevated() {
		mode = "admin"
	}
	dir := filepath.Join(base, "sshtun", "webview-"+mode)
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// hideConsole 隐藏随控制台子系统一同创建的窗口，使 GUI 模式不残留黑框。
func hideConsole() {
	h, _, _ := procGetConsoleWindow.Call()
	if h == 0 {
		return
	}
	_, _, _ = procShowWindow.Call(h, swHide)
}

// waitSignal 阻塞直到收到中断/终止信号。
func waitSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	signal.Stop(ch)
}

// showFatal 在 GUI 模式下用消息框报告致命错误（控制台已隐藏时也能看到）。
func showFatal(err error) {
	fmt.Fprintln(os.Stderr, "错误:", err)
	showError("sshtun-gui", err.Error())
}

// showError 用系统消息框提示错误（GUI 子系统没有控制台可打印）。
func showError(title, msg string) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(msg)
	_, _, _ = procMessageBox.Call(0,
		uintptr(unsafe.Pointer(m)),
		uintptr(unsafe.Pointer(t)),
		mbOK|mbIconError)
}

/* ---------------------------------- DPI ---------------------------------- */

// enableDpiAwareness 声明进程 DPI 感知，让窗口与内嵌 WebView2 按显示器 DPI 原生渲染，
// 避免高分辨率屏上整个界面被系统位图拉伸而字体模糊。必须在创建任何窗口前调用。
func enableDpiAwareness() {
	// 首选 Per-Monitor V2（Windows 10 1703+，跨不同 DPI 显示器时自动重算缩放）。
	if err := procSetProcessDpiAwarenessContext.Find(); err == nil {
		if r, _, _ := procSetProcessDpiAwarenessContext.Call(dpiAwarenessPerMonitorV2); r != 0 {
			return
		}
	}
	// 退而求其次：Per-Monitor（Windows 8.1+）。
	if err := procSetProcessDpiAwareness.Find(); err == nil {
		if r, _, _ := procSetProcessDpiAwareness.Call(processPerMonitorDpiAware); r == 0 {
			return
		}
	}
	// 兜底：System Aware（Windows Vista+）。
	if err := procSetProcessDPIAware.Find(); err == nil {
		_, _, _ = procSetProcessDPIAware.Call()
	}
}

// systemDpi 返回系统 DPI（96 为 100% 基准）；接口不可用时按 96 处理。
func systemDpi() int {
	if err := procGetDpiForSystem.Find(); err == nil {
		if d, _, _ := procGetDpiForSystem.Call(); d != 0 {
			return int(d)
		}
	}
	return 96
}

// scaledPx 把逻辑尺寸按系统 DPI 换算成物理像素。
func scaledPx(v int) int {
	return v * systemDpi() / 96
}

/* -------------------------------- 单实例 -------------------------------- */

// acquireSingleton 尝试取得单实例互斥体，返回是否已有实例在运行。
// 无论是否已存在都持有句柄，进程退出时由系统回收：
// 提权重启产生的新实例借此在旧实例退出后继续占住名字，避免被后续启动重复拉起。
func acquireSingleton() bool {
	name, _ := windows.UTF16PtrFromString(singletonMutexName)
	h, err := windows.CreateMutex(nil, false, name)
	if h == 0 {
		return false // 创建失败：放弃限制，按新实例继续运行
	}
	singletonMutex = h
	return err == windows.ERROR_ALREADY_EXISTS
}

// focusExisting 唤醒已在运行的实例：等待其窗口出现后还原并置于前台。
// 第二个实例可能在首个实例窗口创建前就启动，因此这里轮询等待一段时间。
func focusExisting() {
	title, _ := windows.UTF16PtrFromString(winTitle)
	deadline := time.Now().Add(8 * time.Second)
	for {
		if hwnd, _, _ := procFindWindow.Call(0, uintptr(unsafe.Pointer(title))); hwnd != 0 {
			_, _, _ = procShowWindow.Call(hwnd, swRestore) // 从隐藏/最小化还原
			_, _, _ = procSetForegroundWin.Call(hwnd)
			return
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(120 * time.Millisecond)
	}
}

/* ------------------------------- 提权重启 ------------------------------- */

// watchElevation 轮询后端 /api/session，发现「以管理员身份重启」请求后重启本程序。
// 这是提权的唯一入口：sshtun web 自身不做任何提权，只把请求交给 GUI 处理。
func watchElevation(url string, b *backend) {
	client := &http.Client{Timeout: 800 * time.Millisecond}
	var resp struct {
		Elevate *struct {
			Action string   `json:"action"`
			Names  []string `json:"names"`
		} `json:"elevate"`
	}
	for {
		time.Sleep(500 * time.Millisecond)
		if atomic.LoadInt32(&quitting) != 0 || b.exited() {
			return
		}
		r, err := apiGet(client, url+"/api/session")
		if err != nil {
			continue
		}
		resp.Elevate = nil
		_ = json.NewDecoder(r.Body).Decode(&resp)
		_ = r.Body.Close()
		if resp.Elevate != nil {
			if err := relaunchElevated(resp.Elevate.Action, resp.Elevate.Names); err != nil {
				// 用户取消 UAC：后端与窗口保持原状，可再次尝试。
				showError("已取消管理员授权", "未获得管理员权限，后台服务保持原样运行。\n\n"+err.Error())
			}
			return
		}
	}
}

// relaunchElevated 以管理员身份（UAC）重启本程序，并把待执行动作透传给新实例续跑。
// 成功拉起新实例后本进程随即退出；用户取消授权时返回错误，由调用方决定后续处理。
func relaunchElevated(action string, names []string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("定位自身路径失败: %w", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		wd = filepath.Dir(self)
	}

	// 剔除上一次透传的动作与标记避免叠加，再附加本次待执行动作。
	// --_elevated 告知新实例「由提权重启产生」，从而不因旧实例仍在运行而退出。
	// 新实例会自行生成访问令牌；这里不能覆盖当前进程的令牌——随后还要用它
	// 请求旧后端优雅停止隧道。
	tok, terr := newBackendToken()
	if terr != nil {
		return fmt.Errorf("生成访问令牌失败: %w", terr)
	}
	argv := make([]string, 0, len(os.Args)+5)
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, "--_action=") || strings.HasPrefix(a, "--_names=") || a == "--_elevated" {
			continue
		}
		argv = append(argv, a)
	}
	if action != "" {
		argv = append(argv, "--_action="+action)
	}
	if len(names) > 0 {
		argv = append(argv, "--_names="+strings.Join(names, ","))
	}
	argv = append(argv, "--_token="+tok, "--_elevated")

	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(self)
	argp, _ := windows.UTF16PtrFromString(joinWindowsArgs(argv))
	cwd, _ := windows.UTF16PtrFromString(wd)
	if err := windows.ShellExecute(0, verb, file, argp, cwd, swShow); err != nil {
		// 用户取消 UAC（错误码 1223）：由调用方决定是提示后继续还是终止。
		return err
	}

	// 新实例已拉起：释放托盘、优雅结束后端并关闭本窗口。
	removeTrayIcon()
	if backendRef != nil {
		backendRef.shutdown(backendURL, 8*time.Second)
		backendRef.kill()
	}
	if trayHwnd != 0 {
		quitApp(uintptr(trayHwnd))
	} else {
		os.Exit(0)
	}
	return nil
}

// joinWindowsArgs 按 Windows 命令行解析规则（CommandLineToArgvW / CRT 启动代码）拼接参数串。
// ShellExecute 只接受一整条命令串，含空格的参数必须加引号，否则会被拆断。
func joinWindowsArgs(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = quoteWindowsArg(a)
	}
	return strings.Join(parts, " ")
}

// quoteWindowsArg 为单个参数按需加双引号，并转义其中的反斜杠与引号。
func quoteWindowsArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, r := range s {
		switch r {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat("\\", slashes*2+1))
			slashes = 0
			b.WriteByte('"')
		default:
			b.WriteString(strings.Repeat("\\", slashes))
			slashes = 0
			b.WriteRune(r)
		}
	}
	b.WriteString(strings.Repeat("\\", slashes*2))
	b.WriteByte('"')
	return b.String()
}

// isElevated 报告当前进程是否以管理员身份运行。
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
