/* sshtun Web 界面的中英双语资源与切换逻辑（无框架、无外部依赖）。 */
(function (global) {
  "use strict";

  /* 文案表：key -> { zh, en }。新增界面文案时在此登记一条即可。 */
  const DICT = {
    /* ------------------------------ 应用 ------------------------------ */
    "app.title":                { zh: "sshtun · 隧道管理器", en: "sshtun · Tunnel Manager" },

    /* ---------------------------- 顶部工具栏 ---------------------------- */
    "nav.logs.title":           { zh: "查看运行日志", en: "View the runtime log" },
    "nav.theme":                { zh: "主题", en: "Theme" },
    "nav.logout":               { zh: "退出登录", en: "Sign out" },

    /* ------------------------------ 通用 ------------------------------ */
    "common.close":             { zh: "关闭", en: "Close" },
    "common.cancel":            { zh: "取消", en: "Cancel" },
    "common.save":              { zh: "保存", en: "Save" },
    "common.saving":            { zh: "保存中…", en: "Saving…" },
    "common.refresh":           { zh: "刷新", en: "Refresh" },
    "common.running":           { zh: "运行中", en: "Running" },
    "common.stopped":           { zh: "已停止", en: "Stopped" },
    "common.enabled":           { zh: "已启用", en: "Enabled" },
    "common.disabled":          { zh: "停用", en: "Disabled" },
    "common.disabledMarked":    { zh: "已停用", en: "Disabled" },
    "common.enable":            { zh: "启用 %s", en: "Enable %s" },
    "common.user":              { zh: "用户 %s", en: "User %s" },
    "common.password":          { zh: "密码", en: "Password" },
    "common.download":          { zh: "下载", en: "Download" },
    "common.upload":            { zh: "上传", en: "Upload" },
    "common.routes":            { zh: "路由", en: "Routes" },
    "common.forwards":          { zh: "端口转发", en: "Port forwarding" },
    "common.tun":               { zh: "TUN 网卡", en: "TUN interface" },
    "common.keyFile":           { zh: "私钥文件", en: "Private key file" },
    "common.noRoutes":          { zh: "暂无路由", en: "No routes" },
    "common.noForwards":        { zh: "暂无端口转发", en: "No port forwards" },
    "common.remove":            { zh: "移除", en: "Remove" },
    "common.unspecified":       { zh: "未指定", en: "Not specified" },
    "common.logs":              { zh: "日志", en: "Logs" },
    "common.passwordSet":       { zh: "已设置（留空表示不修改）", en: "Already set (leave blank to keep it)" },

    /* ------------------------------ 概览 ------------------------------ */
    "overview.title":           { zh: "隧道概览", en: "Tunnel overview" },
    "overview.hint":            { zh: "当前实例", en: "Current instance" },
    "overview.traffic":         { zh: "全局流量", en: "Global traffic" },
    "overview.trafficIdle":     { zh: "当前无运行中的隧道", en: "No running tunnels" },
    "overview.trafficRunning":  { zh: "统计运行中隧道的经隧道流量", en: "Traffic of the running tunnels" },
    "overview.live":            { zh: "实时", en: "Live" },
    "overview.totalTunnels":    { zh: "隧道总数", en: "Total tunnels" },
    "overview.mode":            { zh: "运行模式", en: "Mode" },
    "overview.privWaiting":     { zh: "等待授权中", en: "Waiting for approval" },
    "overview.privOk":          { zh: "管理员权限", en: "Administrator" },
    "overview.privNeed":        { zh: "需要提权", en: "Elevation required" },
    "overview.privChecking":    { zh: "权限检测中…", en: "Checking privileges…" },
    "overview.privTitle":       { zh: "是否具备创建 TUN 与修改路由的权限", en: "Whether the process may create TUN interfaces and modify the routing table" },
    "overview.statusChecking":  { zh: "状态检测中…", en: "Checking status…" },
    "overview.statusTitle":     { zh: "实例运行状态", en: "Instance running status" },
    "overview.runningPid":      { zh: "运行中 · pid %s", en: "Running · pid %s" },
    "overview.notRunning":      { zh: "未运行", en: "Not running" },

    /* ----------------------------- 隧道表 ----------------------------- */
    "tunnels.title":            { zh: "隧道", en: "Tunnels" },
    "tunnels.filter.all":       { zh: "全部", en: "All" },
    "tunnels.new":              { zh: "＋ 新建隧道", en: "+ New tunnel" },
    "tunnels.th.endpoint":      { zh: "SSH 端点", en: "SSH endpoint" },
    "tunnels.th.actions":       { zh: "操作", en: "Actions" },
    "tunnels.empty.title":      { zh: "还没有任何隧道", en: "No tunnels yet" },
    "tunnels.empty.desc":       { zh: "创建第一条隧道，填写 SSH 服务器与网卡信息即可开始。", en: "Create your first tunnel by filling in the SSH server and the interface details." },
    "tunnels.empty.cta":        { zh: "创建隧道", en: "Create tunnel" },
    "tunnels.noMatch":          { zh: "没有符合筛选条件的隧道", en: "No tunnels match the current filter" },
    "tunnels.detail":           { zh: "详情", en: "Details" },
    "tunnels.detail.title":     { zh: "查看详情", en: "View details" },

    /* ------------------------------ 动作 ------------------------------ */
    "act.start":                { zh: "启动", en: "Start" },
    "act.stop":                 { zh: "停止", en: "Stop" },
    "act.restart":              { zh: "重启", en: "Restart" },
    "act.edit":                 { zh: "编辑", en: "Edit" },
    "act.delete":               { zh: "删除", en: "Delete" },
    "act.startAll":             { zh: "启动全部", en: "Start all" },
    "act.stopAll":              { zh: "停止全部", en: "Stop all" },
    "act.restartAll":           { zh: "重启全部", en: "Restart all" },
    "act.starting":             { zh: "启动中…", en: "Starting…" },
    "act.stopping":             { zh: "停止中…", en: "Stopping…" },
    "act.restarting":           { zh: "重启中…", en: "Restarting…" },
    "act.started":              { zh: "已启动 %s", en: "Started %s" },
    "act.stopped":              { zh: "已停止 %s", en: "Stopped %s" },
    "act.restarted":            { zh: "已重启 %s", en: "Restarted %s" },
    "act.enabled":              { zh: "已启用 %s", en: "Enabled %s" },
    "act.disabled":             { zh: "已停用 %s", en: "Disabled %s" },
    "act.startedAll":           { zh: "已启动全部启用隧道", en: "Started all enabled tunnels" },
    "act.stoppedAll":           { zh: "已停止全部隧道", en: "Stopped all tunnels" },
    "act.restartedAll":         { zh: "已重启全部隧道", en: "Restarted all tunnels" },
    "act.notApplied":           { zh: "操作已提交，但隧道未进入预期状态，请查看日志", en: "The action was submitted, but the tunnel did not reach the expected state. Please check the logs" },

    /* --------------------------- 隧道编辑弹窗 --------------------------- */
    "tunnel.new":               { zh: "新建隧道", en: "New tunnel" },
    "tunnel.editTitle":         { zh: "编辑隧道 · %s", en: "Edit tunnel · %s" },
    "tunnel.sub.new":           { zh: "填写 SSH 服务器与分流网段即可开始", en: "Enter the SSH server and the subnets to split to get started" },
    "tunnel.sub.edit":          { zh: "修改后保存即生效（运行中的隧道需重启后应用）", en: "Changes take effect once saved (running tunnels need a restart)" },
    "tunnel.basic":             { zh: "基本信息", en: "Basic info" },
    "tunnel.basic.hint":        { zh: "隧道名用于命令行与配置", en: "The tunnel name is used on the command line and in the configuration" },
    "tunnel.name":              { zh: "隧道名", en: "Tunnel name" },
    "tunnel.nameNote1":         { zh: "隧道名不可包含空格与 ", en: "The tunnel name cannot contain spaces or " },
    "tunnel.nameNote2":         { zh: " 等字符，也不能以 ", en: " and other characters, and cannot end with " },
    "tunnel.nameNote3":         { zh: " 结尾；最长 32 个字符，且不能取保留名 ", en: " — it can be at most 32 characters long and cannot use the reserved name " },
    "tunnel.nameNote4":         { zh: "。", en: "." },
    "tunnel.nameEmpty":         { zh: "隧道名不能为空", en: "The tunnel name cannot be empty" },
    "tunnel.nameTooLong":       { zh: "隧道名过长（最多 32 个字符）", en: "The tunnel name is too long (at most 32 characters)" },
    "tunnel.nameReserved":      { zh: "隧道名不能是保留名 \"all\"（它表示「全部隧道」）", en: "The tunnel name cannot be the reserved name \"all\" (it means \"all tunnels\")" },
    "tunnel.nameSpace":         { zh: "隧道名不能包含空格", en: "The tunnel name cannot contain spaces" },
    "tunnel.nameBadChar":       { zh: "隧道名不能包含文件名不允许的字符：\"%s\"", en: "The tunnel name contains a character that is not allowed in a file name: \"%s\"" },
    "tunnel.nameDot":           { zh: "隧道名不能以 . 结尾", en: "The tunnel name cannot end with ." },
    "tunnel.ssh":               { zh: "SSH 连接", en: "SSH connection" },
    "tunnel.ssh.hint":          { zh: "凭据加密保存在本地数据库", en: "Credentials are encrypted and stored in the local database" },
    "tunnel.sshHost":           { zh: "SSH 服务器", en: "SSH server" },
    "tunnel.sshHost.placeholder": { zh: "1.2.3.4 或 example.com", en: "1.2.3.4 or example.com" },
    "tunnel.sshPort":           { zh: "SSH 端口", en: "SSH port" },
    "tunnel.sshUser":           { zh: "SSH 用户", en: "SSH user" },
    "tunnel.authMethod":        { zh: "认证方式", en: "Authentication method" },
    "tunnel.auth.key":          { zh: "私钥 (key)", en: "Private key (key)" },
    "tunnel.auth.password":     { zh: "密码 (password)", en: "Password (password)" },
    "tunnel.loginPassword":     { zh: "登录密码", en: "Login password" },
    "tunnel.pwd.invalidated":    { zh: "连接地址已修改，保存后需重新输入密码", en: "The connection address changed; the password must be entered again after saving" },
    "tunnel.hostKey":           { zh: "主机指纹校验", en: "Host key verification" },
    "tunnel.hostKey.title":     { zh: "accept-new = 首次自动信任；strict = 严格校验；none = 不校验（不安全）", en: "accept-new = trust on first use; strict = strict verification; none = no verification (insecure)" },
    "tunnel.tun.hint":          { zh: "虚拟网卡参数，Windows 下需 wintun 驱动", en: "Virtual interface settings; the wintun driver is required on Windows" },
    "tunnel.tunName":           { zh: "网卡名", en: "Interface name" },
    "tunnel.tunAddress":        { zh: "网卡地址", en: "Interface address" },
    "tunnel.routes.hint":       { zh: "决定哪些网段走隧道，bypass 为强制直连", en: "Which subnets go through the tunnel; bypass forces a direct connection" },
    "tunnel.routes.placeholder": { zh: "10.0.0.0/8 或 1.2.3.4", en: "10.0.0.0/8 or 1.2.3.4" },
    "tunnel.addRoute":          { zh: "添加路由", en: "Add route" },
    "tunnel.forwards.hint":     { zh: "local = -L，remote = -R", en: "local = -L, remote = -R" },
    "tunnel.fw.bindHost":       { zh: "监听地址（默认 127.0.0.1）", en: "Bind address (default 127.0.0.1)" },
    "tunnel.fw.bindPort":       { zh: "监听端口", en: "Bind port" },
    "tunnel.fw.host":           { zh: "目标主机", en: "Target host" },
    "tunnel.fw.port":           { zh: "目标端口", en: "Target port" },
    "tunnel.addForward":        { zh: "添加转发", en: "Add forward" },
    "tunnel.delete":            { zh: "删除隧道", en: "Delete tunnel" },
    "tunnel.deleteConfirm":     { zh: "确定删除隧道 “%s”？该操作不可撤销。", en: "Delete tunnel “%s”? This action cannot be undone." },
    "tunnel.deleted":           { zh: "已删除 %s", en: "Deleted %s" },
    "tunnel.saved":             { zh: "已保存 %s", en: "Saved %s" },
    "tunnel.userEmpty":         { zh: "SSH 用户名不能为空", en: "The SSH user name cannot be empty" },
    "tunnel.keyRequired":       { zh: "认证方式为私钥时必须指定私钥文件", en: "A private key file is required when the authentication method is a private key" },
    "tunnel.routeRequired":     { zh: "请输入 IP 或网段", en: "Please enter an IP address or a subnet" },
    "tunnel.routeExists":       { zh: "该路由已存在", en: "This route already exists" },
    "tunnel.fwPortInvalid":     { zh: "监听端口非法", en: "Invalid bind port" },
    "tunnel.fwTargetInvalid":   { zh: "目标主机/端口非法", en: "Invalid target host/port" },
    "tunnel.fwExists":          { zh: "该方向的监听端口已存在", en: "A forward with this bind port already exists in this direction" },

    /* --------------------------- 隧道详情抽屉 --------------------------- */
    "tunnel.detail":            { zh: "隧道详情", en: "Tunnel details" },
    "tunnel.enableLabel":       { zh: "启用该隧道", en: "Enable this tunnel" },
    "tunnel.conn":              { zh: "连接参数", en: "Connection" },
    "tunnel.peerIP":            { zh: "对端 IP", en: "Peer IP" },
    "tunnel.auth":              { zh: "认证", en: "Authentication" },
    "tunnel.authKey":           { zh: "私钥 · %s", en: "Private key · %s" },
    "tunnel.fingerprint":       { zh: "指纹", en: "Fingerprint" },
    "tunnel.noVerify":          { zh: "不校验（不安全）", en: "Not verified (insecure)" },
    "tunnel.traffic":           { zh: "流量", en: "Traffic" },
    "traffic.total":            { zh: "累计 %s", en: "Total %s" },

    /* --------------------------- 凭据修正弹窗 --------------------------- */
    "cred.title":               { zh: "SSH 认证失败", en: "SSH authentication failed" },
    "cred.user":                { zh: "SSH 用户名", en: "SSH user name" },
    "cred.password":            { zh: "SSH 密码", en: "SSH password" },
    "cred.password.placeholder": { zh: "重新输入登录密码", en: "Re-enter the login password" },
    "cred.keyPass":             { zh: "私钥口令（可留空）", en: "Private key passphrase (optional)" },
    "cred.keyPass.placeholder": { zh: "私钥口令", en: "Private key passphrase" },
    "cred.hint":                { zh: "凭据会自动加密保存到数据库，随后立即重试启动该隧道。", en: "The credentials are encrypted and saved to the database, then the tunnel is started again immediately." },
    "cred.save":                { zh: "保存并重试", en: "Save and retry" },
    "cred.failed":              { zh: "隧道 %s 启动失败：%s", en: "Tunnel %s failed to start: %s" },
    "cred.rejected":            { zh: "认证被服务端拒绝", en: "Authentication was rejected by the server" },
    "cred.enterPassword":       { zh: "请重新输入 SSH 密码", en: "Please re-enter the SSH password" },
    "cred.keyPathRequired":     { zh: "请指定私钥文件路径", en: "Please specify the private key file path" },
    "cred.saved":               { zh: "已保存 %s 的凭据", en: "Saved the credentials of %s" },

    /* ----------------------------- 设置弹窗 ----------------------------- */
    "settings.title":           { zh: "设置", en: "Settings" },
    "settings.save":            { zh: "保存设置", en: "Save settings" },
    "settings.saved":           { zh: "设置已保存", en: "Settings saved" },
    "settings.readFailed":      { zh: "读取设置失败: %s", en: "Failed to read the settings: %s" },
    "settings.openFailed":      { zh: "打开设置失败", en: "Failed to open the settings" },
    "settings.logs.hint":       { zh: "输出位置与级别", en: "Output destination and level" },
    "settings.logLevel":        { zh: "日志级别", en: "Log level" },
    "settings.logDir":          { zh: "日志目录", en: "Log directory" },
    "settings.logDir.placeholder": { zh: "log（留空表示只输出到控制台）", en: "log (leave blank to output to the console only)" },
    "settings.logConsole":      { zh: "控制台输出", en: "Console output" },
    "settings.logConsole.auto": { zh: "auto（前台输出）", en: "auto (foreground output)" },
    "settings.logConsole.true": { zh: "true（始终输出）", en: "true (always output)" },
    "settings.logConsole.false": { zh: "false（仅写文件）", en: "false (write to files only)" },
    "settings.sshCommon":       { zh: "SSH 通用参数", en: "Common SSH settings" },
    "settings.sshCommon.hint":  { zh: "对所有隧道生效", en: "Applied to every tunnel" },
    "settings.connectTimeout":  { zh: "连接超时（秒）", en: "Connect timeout (seconds)" },
    "settings.keepalive":       { zh: "保活间隔（秒）", en: "Keepalive interval (seconds)" },
    "settings.appearance":      { zh: "界面外观", en: "Appearance" },
    "settings.appearance.hint": { zh: "语言与主题，未配置时跟随系统", en: "Language and theme; follows the system when unset" },
    "settings.language":        { zh: "界面语言", en: "Interface language" },
    "settings.language.auto":   { zh: "自动（跟随系统）", en: "Automatic (follow the system)" },
    "settings.language.zh":     { zh: "简体中文", en: "Simplified Chinese" },
    "settings.language.en":     { zh: "English", en: "English" },
    "settings.theme":           { zh: "界面主题", en: "Interface theme" },
    "settings.theme.auto":      { zh: "自动（跟随系统）", en: "Automatic (follow the system)" },
    "settings.theme.light":     { zh: "浅色", en: "Light" },
    "settings.theme.dark":      { zh: "深色", en: "Dark" },
    "settings.web":             { zh: "Web 服务", en: "Web service" },
    "settings.web.hint":        { zh: "监听地址/端口与密码需重启 sshtun 生效", en: "The bind address/port and the password take effect after restarting sshtun" },
    "settings.web.hostname":    { zh: "监听地址", en: "Bind address" },
    "settings.web.port":        { zh: "端口", en: "Port" },
    "settings.web.username":    { zh: "用户名", en: "Username" },
    "settings.web.password":    { zh: "访问密码", en: "Access password" },
    "settings.web.password.hint": { zh: "留空表示不修改", en: "Leave blank to keep the current value" },
    "settings.web.password.unset": { zh: "未设置（留空表示免登录）", en: "Not set (leave blank to disable sign-in)" },
    "settings.web.cors":        { zh: "CORS 允许来源", en: "CORS allowed origins" },
    "settings.web.cors.hint":   { zh: "逗号分隔，* 表示允许任意源", en: "Comma-separated; * allows any origin" },
    "settings.other":           { zh: "其他", en: "Other" },
    "settings.other.hint":      { zh: "数据库与 tun2socks 位置", en: "Locations of the database and tun2socks" },
    "settings.db":              { zh: "数据库路径", en: "Database path" },
    "settings.tun2socks":       { zh: "tun2socks 路径", en: "tun2socks path" },
    "settings.tun2socks.placeholder": { zh: "留空表示自动查找", en: "Leave blank to search automatically" },

    /* ----------------------------- 日志抽屉 ----------------------------- */
    "logs.title":               { zh: "运行日志", en: "Runtime log" },
    "logs.titleFor":            { zh: "运行日志 · %s", en: "Runtime log · %s" },
    "logs.filter.title":        { zh: "按隧道筛选日志", en: "Filter the logs by tunnel" },
    "logs.lines.title":         { zh: "显示行数", en: "Number of lines" },
    "logs.reload.title":        { zh: "立即重新读取日志", en: "Reload the logs right now" },
    "logs.auto":                { zh: "自动刷新", en: "Auto refresh" },
    "logs.autoOn":              { zh: "自动·开", en: "Auto·on" },
    "logs.auto.title":          { zh: "自动刷新日志并跳到最新一条", en: "Refresh the logs automatically and jump to the latest entry" },
    "logs.interval.title":      { zh: "自动刷新间隔", en: "Auto refresh interval" },
    "logs.interval.2":          { zh: "2 秒", en: "2 s" },
    "logs.interval.5":          { zh: "5 秒", en: "5 s" },
    "logs.interval.10":         { zh: "10 秒", en: "10 s" },
    "logs.interval.30":         { zh: "30 秒", en: "30 s" },
    "logs.interval.60":         { zh: "1 分钟", en: "1 min" },
    "logs.allTunnels":          { zh: "全部隧道", en: "All tunnels" },
    "logs.loading":             { zh: "加载中…", en: "Loading…" },
    "logs.empty":               { zh: "（空）", en: "(empty)" },
    "logs.readFailed":          { zh: "读取日志失败: %s", en: "Failed to read the logs: %s" },

    /* ----------------------------- 登录页 ----------------------------- */
    "login.sub":                { zh: "请输入访问凭据以管理隧道", en: "Enter your credentials to manage the tunnels" },
    "login.submit":             { zh: "登录", en: "Sign in" },
    "login.welcome":            { zh: "欢迎，%s", en: "Welcome, %s" },
    "login.badToken":           { zh: "访问令牌无效，请从 sshtun-gui 窗口重新打开界面。", en: "The access token is invalid. Please open the interface again from the sshtun-gui window." },

    /* ---------------------------- 权限 / 提权 ---------------------------- */
    "elevate.title":            { zh: "需要管理员权限", en: "Administrator privileges required" },
    "elevate.notice":           { zh: "启动/重启隧道会创建 TUN 网卡并修改系统路由，程序不会自动提权。", en: "Starting or restarting a tunnel creates a TUN interface and modifies the system routing table; the program does not elevate privileges on its own." },
    "elevate.viewHelp":         { zh: "查看处理方法", en: "See how to fix this" },
    "elevate.sub":              { zh: "启动/重启隧道会创建 TUN 网卡并修改系统路由。", en: "Starting or restarting a tunnel creates a TUN interface and modifies the system routing table." },
    "elevate.waiting":          { zh: "等待管理员授权", en: "Waiting for administrator approval" },
    "elevate.restarting":       { zh: "sshtun-gui 正在以管理员身份重新启动，请在系统授权窗口中确认…", en: "sshtun-gui is restarting with administrator privileges; please confirm in the system authorization dialog…" },
    "elevate.running":          { zh: "已在管理员权限下运行", en: "Now running with administrator privileges" },
    "elevate.rerun":            { zh: "请在管理员权限下重新运行程序", en: "Please run the program again with administrator privileges" },
    "elevate.ready":            { zh: "管理员实例已就绪", en: "The administrator instance is ready" },
    "elevate.timeoutTitle":     { zh: "提权未完成", en: "Elevation did not complete" },
    "elevate.timeoutSub":       { zh: "等待管理员实例超时。若已取消授权，可重试；或从托盘退出后以管理员身份重新打开。", en: "Timed out waiting for the administrator instance. If the prompt was dismissed you can retry; or quit from the tray and reopen it as administrator." },
    "elevate.go":               { zh: "以管理员身份重启", en: "Restart as administrator" },
    "elevate.retry":            { zh: "重试", en: "Retry" },
    "elevate.hintWindows":      { zh: "程序不会自动提权。请关闭本程序后，右键 sshtun.exe 选择「以管理员身份运行」，再执行 sshtun web。", en: "The program does not elevate privileges on its own. Close it, right-click sshtun.exe, choose “Run as administrator”, then run sshtun web again." },
    "elevate.hintUnix":         { zh: "程序不会自动提权。请关闭本程序后执行：sudo sshtun web", en: "The program does not elevate privileges on its own. Close it and run: sudo sshtun web" },

    /* ------------------------------ 主题 ------------------------------ */
    "theme.auto":               { zh: "跟随系统", en: "Follow the system" },
    "theme.light":              { zh: "亮色", en: "Light" },
    "theme.dark":               { zh: "深色", en: "Dark" },
    "theme.label":              { zh: "主题：%s（点击切换）", en: "Theme: %s (click to switch)" },
    "theme.current":            { zh: "主题：%s", en: "Theme: %s" },

    /* ---------------------------- 错误提示 ---------------------------- */
    "error.unauthorized":       { zh: "未登录或会话已过期", en: "Not signed in or the session has expired" },
    "error.requestFailed":      { zh: "请求失败: %s", en: "Request failed: %s" },
    "error.login":              { zh: "登录失败", en: "Sign-in failed" },
    "error.noService":          { zh: "无法连接本地服务，请确认 sshtun 正在运行", en: "Cannot connect to the local service; make sure sshtun is running" },
  };

  /* 当前语言："zh" 或 "en"。 */
  let LANG = "zh";

  /* 已应用过文案的元素，用于切换语言时重复套用。 */
  const APPLIED = new WeakSet();

  /**
   * 检测客户端系统语言：优先浏览器报告的首选语言，zh 开头视为中文，其余为英文。
   */
  function detectLang() {
    const list = (navigator.languages && navigator.languages.length)
      ? navigator.languages
      : [navigator.language || ""];
    for (const l of list) {
      if (!l) continue;
      const tag = String(l).toLowerCase();
      if (tag === "zh" || tag.startsWith("zh-") || tag.startsWith("zh_")) return "zh";
      return "en";
    }
    return "en";
  }

  /**
   * 解析最终语言：配置值优先；为空或 auto 时按客户端系统语言选择。
   */
  function resolveLang(configured) {
    const v = String(configured || "").trim().toLowerCase();
    if (v === "zh" || v === "en") return v;
    return detectLang();
  }

  /**
   * 取文案：t("key") 返回当前语言的文本；未登记的 key 原样返回，便于排查缺漏。
   */
  function t(key) {
    const item = DICT[key];
    if (!item) return key;
    return item[LANG] || item.zh || item.en || key;
  }

  /**
   * 套用文案到单个元素：data-i18n（文本）、data-i18n-placeholder、
   * data-i18n-title、data-i18n-aria-label。
   */
  function applyTo(el) {
    const key = el.getAttribute("data-i18n");
    if (key) el.textContent = t(key);

    const ph = el.getAttribute("data-i18n-placeholder");
    if (ph) el.setAttribute("placeholder", t(ph));

    const ti = el.getAttribute("data-i18n-title");
    if (ti) el.setAttribute("title", t(ti));

    const al = el.getAttribute("data-i18n-aria-label");
    if (al) el.setAttribute("aria-label", t(al));
  }

  /**
   * 切换语言并重新套用文案。lang 省略时按 detectLang() 自动选择。
   */
  function applyLang(lang) {
    LANG = lang === "zh" || lang === "en" ? lang : detectLang();
    document.documentElement.setAttribute("data-lang", LANG);
    document.documentElement.setAttribute("lang", LANG === "zh" ? "zh-CN" : "en");
    // 遍历整个文档：弹窗、抽屉与登录遮罩都在 #app 之外，只扫 #app 会漏掉它们。
    document.querySelectorAll("[data-i18n],[data-i18n-placeholder],[data-i18n-title],[data-i18n-aria-label]").forEach(applyTo);
    // 页面标题单独处理（title 不在 body 内）。
    const title = document.querySelector("title[data-i18n]");
    if (title) title.textContent = t(title.getAttribute("data-i18n"));
    return LANG;
  }

  global.I18N = {
    dict: DICT,
    t: t,
    get lang() { return LANG; },
    detectLang: detectLang,
    resolveLang: resolveLang,
    applyLang: applyLang,
    register(obj) {
      for (const k in obj) {
        DICT[k] = obj[k];
      }
    },
  };
})(window);
