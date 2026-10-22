/* sshtun GUI 前端逻辑（无框架、无外部依赖）。 */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  // fmt 按顺序把模板里的 %s 替换为实参（中英文案共用同一套占位符）。
  const fmt = (s, ...a) => a.reduce((x, v) => x.replace("%s", v), s);
  const TOKEN_KEY = "sshtun_token";
  const THEME_KEY = "sshtun_theme";
  let TOKEN = sessionStorage.getItem(TOKEN_KEY) || "";
  let NEED_LOGIN = false;
  let MANAGED = false; // 由 sshtun-gui 拉起：可由 GUI 自我提权重启
  let PLATFORM = "";   // 后端平台（windows/linux/darwin），用于给出对应的重启命令

  // GUI 托管实例通过 ?t= 传入一次性访问令牌：存入 sessionStorage 并立即从地址栏清除，
  // 后续请求统一走 X-Token 头（避免令牌留在地址/历史记录中）。
  (function bootstrapToken() {
    try {
      const u = new URL(location.href);
      const t = u.searchParams.get("t");
      if (!t) return;
      sessionStorage.setItem(TOKEN_KEY, t);
      TOKEN = t;
      u.searchParams.delete("t");
      history.replaceState(null, "", u.pathname + (u.search ? u.search : "") + u.hash);
    } catch (e) { /* 忽略 */ }
  })();

  const state = {
    overview: null,
    tunnels: [],
    stats: null,   // { tunnels: {name: sample}, total: sample }
    editing: null, // { isNew, base, routes: [], forwards: [] }
    editAddr: null, // 编辑弹窗打开时的连接地址 { host, port }
    cred: null,    // 凭据修正弹窗当前对应的隧道名 { name }
    elevating: false,
    pending: null, // 待执行的提权动作 { action, names }
    busy: {},      // 隧道名 -> 进行中的操作（start|stop|restart）
    globalBusy: null, // 顶部批量操作的进行中操作
    logTunnel: "", // 日志抽屉当前过滤的隧道名（空表示全部）
    logAuto: false, // 日志是否自动刷新
    logTimer: null, // 日志自动刷新的定时器
    selected: "",  // 检视器当前展示的隧道名
    filter: "all", // 隧道表筛选：all | running | stopped | off
    spark: { down: [0], up: [0], ts: [0] }, // 全局速率迷你趋势（ts 为采样时刻）
    sparkAt: 0,
    timer: null,
    booted: false,
    refreshing: false, // 是否有在途刷新（避免定时器与手动刷新叠加请求）
    logFilterKey: "",  // 日志筛选下拉的隧道签名（变化时才重建）
    lastFocus: null,   // 打开弹窗/抽屉前的焦点元素，关闭后归还
  };

  /* ----------------------------- 基础工具 ----------------------------- */

  async function api(method, path, body) {
    const opts = { method, headers: { "X-Token": TOKEN, "Content-Type": "application/json" } };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(path, opts);
    let data = null;
    try { data = await res.json(); } catch (e) { /* 无正文 */ }
    if (res.status === 401) {
      handleUnauthorized();
      throw new Error((data && data.error) || I18N.t("error.unauthorized"));
    }
    if (res.status === 409 && data && data.needAdmin) {
      const e = new Error(data.error || I18N.t("elevate.title"));
      e.needAdmin = true;
      e.action = data.action;
      e.names = data.names;
      throw e;
    }
    if (!res.ok) {
      const msg = (data && data.error) || fmt(I18N.t("error.requestFailed"), res.status);
      throw new Error(msg);
    }
    return data;
  }

  function el(tag, props, children) {
    const node = document.createElement(tag);
    if (props) {
      for (const k in props) {
        if (k === "class") node.className = props[k];
        else if (k === "text") node.textContent = props[k];
        else if (k.startsWith("on")) {
          // 只接受函数形式的事件处理器：字符串会被当作内联脚本执行，构成注入面。
          if (typeof props[k] === "function") node.addEventListener(k.slice(2), props[k]);
        } else node.setAttribute(k, props[k]);
      }
    }
    (children || []).forEach((c) => c && node.appendChild(c));
    return node;
  }

  function toast(msg, kind) {
    const t = el("div", { class: "toast " + (kind || ""), text: msg });
    $("toasts").appendChild(t);
    setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .3s"; }, 3200);
    setTimeout(() => t.remove(), 3600);
  }

  async function act(fn, okMsg) {
    try {
      const r = await fn();
      if (okMsg) toast(okMsg, "ok");
      return r;
    } catch (e) {
      if (e && e.needAdmin) {
        openElevatePrompt(e.action, e.names);
        return null;
      }
      toast(e.message, "err");
      throw e;
    }
  }

  /* ------------------------------ 主题 ------------------------------- */

  // 主题名称对应的文案 key：auto / light / dark（dark 与设置项共用同一条文案）。
  const THEME_NAME = { auto: "theme.auto", light: "theme.light", dark: "theme.dark" };

  // serverTheme 是服务端配置的主题（[web] theme），作为本地偏好缺省时的默认值。
  let serverTheme = "auto";

  function systemTheme() {
    try {
      return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    } catch (e) { return "dark"; }
  }

  function themePref() {
    try {
      const v = localStorage.getItem(THEME_KEY) || serverTheme || "auto";
      return THEME_NAME[v] ? v : "auto";
    } catch (e) { return "auto"; }
  }

  // applyTheme 把当前偏好落到 <html data-theme>；auto 时解析系统/浏览器配色。
  function applyTheme() {
    const pref = themePref();
    const resolved = pref === "auto" ? systemTheme() : pref;
    document.documentElement.setAttribute("data-theme", resolved);
    const btn = $("btn-theme");
    if (btn) {
      // 按钮图标随当前主题变化：auto（跟随系统）/ 亮色 / 深色 各一枚。
      btn.setAttribute("data-mode", pref);
      const label = fmt(I18N.t("theme.label"), I18N.t(THEME_NAME[pref]));
      btn.title = label;
      btn.setAttribute("aria-label", label);
    }
  }

  function cycleTheme() {
    const order = ["auto", "light", "dark"];
    const next = order[(order.indexOf(themePref()) + 1) % order.length];
    try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* 忽略 */ }
    applyTheme();
    toast(fmt(I18N.t("theme.current"), I18N.t(THEME_NAME[next])), "ok");
  }

  function watchSystemTheme() {
    try {
      window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
        if (themePref() === "auto") applyTheme();
      });
    } catch (e) { /* 老浏览器忽略 */ }
  }

  /* ------------------------------ 会话 ------------------------------- */

  function showLogin() {
    $("login").classList.remove("hidden");
    $("app").classList.add("hidden");
    const input = $("login").querySelector("input[name=username]");
    if (input) setTimeout(() => input.focus(), 0);
  }

  function showApp() {
    $("login").classList.add("hidden");
    $("app").classList.remove("hidden");
  }

  function handleUnauthorized() {
    TOKEN = "";
    sessionStorage.removeItem(TOKEN_KEY);
    stopPolling();
    if (NEED_LOGIN) showLogin();
  }

  // stopPolling 停掉后台轮询：登出或进入登录页后不应继续请求受保护接口。
  function stopPolling() {
    if (state.timer) {
      clearInterval(state.timer);
      state.timer = null;
    }
  }

  async function doLogin(ev) {
    if (ev) ev.preventDefault();
    const f = $("form-login");
    const username = f.username.value.trim();
    const password = f.elements.password.value;
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username, password: password }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) throw new Error((data && data.error) || I18N.t("error.login"));
      TOKEN = (data && data.token) || "";
      if (TOKEN) sessionStorage.setItem(TOKEN_KEY, TOKEN);
      NEED_LOGIN = !!(data && data.needLogin);
      f.elements.password.value = "";
      await boot();
      toast(fmt(I18N.t("login.welcome"), (data && data.username) || username), "ok");
    } catch (e) {
      toast(e.message, "err");
    }
  }

  async function doLogout() {
    try { await api("POST", "/api/logout"); } catch (e) { /* 忽略 */ }
    TOKEN = "";
    sessionStorage.removeItem(TOKEN_KEY);
    stopPolling();
    $("modal-edit").classList.add("hidden");
    $("drawer-logs").classList.add("hidden");
    if (NEED_LOGIN) showLogin();
    else location.reload();
  }

  /* ---------------------------- 管理员权限 ---------------------------- */

  // restartHint 给出与平台对应的「以管理员身份重新运行」提示。
  function restartHint() {
    if (PLATFORM === "windows") {
      return I18N.t("elevate.hintWindows");
    }
    return I18N.t("elevate.hintUnix");
  }

  // openElevatePrompt 展示「需要管理员权限」面板：
  // GUI 模式提供「以管理员身份重启」（由 sshtun-gui 自我提权）；
  // 纯 web 模式只提示用户自行以管理员身份重新运行程序。
  function openElevatePrompt(action, names) {
    state.pending = { action: action || "start", names: names || [] };
    state.elevating = false;
    $("elevate-title").textContent = I18N.t("elevate.title");
    $("elevate-sub").textContent = I18N.t("elevate.sub");
    $("elevate-spinner").classList.add("hidden");
    $("btn-elevate-retry").classList.add("hidden");
    $("elevate-mask").classList.remove("hidden");
    if (MANAGED) {
      $("elevate-cmd").classList.add("hidden");
      $("btn-elevate-go").classList.remove("hidden");
    } else {
      $("btn-elevate-go").classList.add("hidden");
      const cmd = $("elevate-cmd");
      cmd.classList.remove("hidden");
      cmd.textContent = restartHint();
    }
  }

  // startElevation 请求 GUI 以管理员身份重启（仅 GUI 托管模式有效）。
  async function startElevation() {
    const p = state.pending || { action: "start", names: [] };
    state.elevating = true;
    $("elevate-title").textContent = I18N.t("elevate.waiting");
    $("elevate-sub").textContent = I18N.t("elevate.restarting");
    $("elevate-spinner").classList.remove("hidden");
    $("btn-elevate-go").classList.add("hidden");
    $("btn-elevate-retry").classList.add("hidden");
    $("elevate-cmd").classList.add("hidden");
    $("elevate-mask").classList.remove("hidden");

    try {
      const r = await api("POST", "/api/elevate", { action: p.action, names: p.names });
      if (!r || !r.elevating) {
        hideElevate();
        state.elevating = false;
        toast(I18N.t("elevate.running"), "ok");
        scheduleRefresh(300);
        return;
      }
      pollRecover();
    } catch (e) {
      state.elevating = false;
      if (e && e.needAdmin) {
        openElevatePrompt(p.action, p.names);
        toast(I18N.t("elevate.rerun"), "err");
        return;
      }
      hideElevate();
      toast(e.message, "err");
    }
  }

  // pollRecover 在 GUI 提权重启期间轮询服务，超时则给出失败提示（不再无限等待）。
  function pollRecover() {
    const deadline = Date.now() + 45000;
    const iv = setInterval(async () => {
      try {
        const s = await fetch("/api/session", { headers: { "X-Token": TOKEN } }).then((r) => (r.ok ? r.json() : null));
        if (s && (!s.needLogin || s.authed)) {
          clearInterval(iv);
          hideElevate();
          state.elevating = false;
          await boot();
          toast(I18N.t("elevate.ready"), "ok");
          return;
        }
      } catch (e) { /* 重启过程中服务暂不可用，继续等待 */ }
      if (Date.now() > deadline) {
        clearInterval(iv);
        state.elevating = false;
        $("elevate-title").textContent = I18N.t("elevate.timeoutTitle");
        $("elevate-sub").textContent = I18N.t("elevate.timeoutSub");
        $("elevate-spinner").classList.add("hidden");
        $("btn-elevate-retry").classList.remove("hidden");
      }
    }, 1200);
  }

  function hideElevate() {
    $("elevate-mask").classList.add("hidden");
    $("elevate-spinner").classList.add("hidden");
    $("btn-elevate-go").classList.add("hidden");
    $("btn-elevate-retry").classList.add("hidden");
  }

  async function boot() {
    let s = null;
    try {
      s = await fetch("/api/session", { headers: { "X-Token": TOKEN } }).then((r) => r.json());
    } catch (e) { /* 服务暂不可用 */ }
    if (!s) {
      // 后端不可用：给出明确提示而不是展示一个空面板。
      showApp();
      toast(I18N.t("error.noService"), "err");
      if (!state.booted) {
        bind();
        state.booted = true;
      }
      return;
    }
    NEED_LOGIN = !!s.needLogin;
    MANAGED = !!s.managed;
    PLATFORM = s.platform || "";
    // 服务端配置的语言优先；未配置（空/auto）时按客户端系统语言选择。
    serverTheme = s.theme || "auto";
    I18N.applyLang(I18N.resolveLang(s.language));
    if (s.username && s.needLogin) {
      $("pill-user").textContent = fmt(I18N.t("common.user"), s.username);
      $("pill-user").classList.remove("hidden");
    }
    $("btn-logout").classList.toggle("hidden", !s.needLogin);
    // GUI 托管实例：令牌无效（例如从浏览器直接打开）时拒绝进入。
    if (s.tokenRequired && !s.authed) {
      showLogin();
      $("login").querySelector(".login-sub").textContent = I18N.t("login.badToken");
      return;
    }
    if (s.needLogin && !s.authed) {
      showLogin();
      return;
    }
    showApp();
    if (!state.booted) {
      bind();
      state.booted = true;
    }
    refresh();
    if (!state.timer) {
      state.timer = setInterval(() => {
        const modalOpen = !$("modal-edit").classList.contains("hidden");
        if (!modalOpen && !state.elevating) refresh();
      }, 4000);
    }
  }

  /* ------------------------------ 渲染 ------------------------------- */

  function renderOverview() {
    const o = state.overview;
    if (!o) return;
    $("pill-ver").textContent = o.version || "dev";

    const priv = $("pill-priv");
    if (state.elevating) {
      priv.className = "pill pill-warn";
      priv.textContent = I18N.t("overview.privWaiting");
    } else if (o.privileged) {
      priv.className = "pill pill-ok";
      priv.textContent = I18N.t("overview.privOk");
    } else {
      priv.className = "pill pill-warn";
      priv.textContent = I18N.t("overview.privNeed");
    }

    const run = $("pill-run");
    if (o.running) {
      run.className = "pill pill-ok";
      run.textContent = fmt(I18N.t("overview.runningPid"), o.pid);
    } else {
      run.className = "pill";
      run.textContent = I18N.t("overview.notRunning");
    }

    $("banner-priv").classList.toggle("hidden", !!(o.privileged || state.elevating));

    $("stats").replaceChildren(
      readout(I18N.t("overview.totalTunnels"), o.tunnelCount),
      readout(I18N.t("common.enabled"), o.enabledCount),
      readout(I18N.t("common.running"), o.runningCount),
      readout(I18N.t("overview.mode"), o.mode || "—")
    );
  }

  function readout(k, v) {
    return el("div", { class: "cell" }, [
      el("div", { class: "k", text: k }),
      el("div", { class: "v", text: String(v) }),
    ]);
  }

  /* ---------------------------- 流量统计显示 ---------------------------- */

  function fmtBytes(n) {
    const p = bytesParts(n);
    return p.num + " " + p.unit;
  }

  // bytesParts 返回「数值 + 单位」，供速率与累计流量共用。
  function bytesParts(n) {
    n = Number(n) || 0;
    if (n < 1024) return { num: String(Math.round(n)), unit: "B" };
    const units = ["KB", "MB", "GB", "TB", "PB"];
    let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
    return { num: (n >= 100 ? n.toFixed(0) : n.toFixed(1)), unit: units[i] };
  }

  function fmtRate(bps) {
    return fmtBytes(bps) + "/s";
  }

  // fmtRateParts 把速率拆成「数值 + 单位」，便于大字排版。
  function fmtRateParts(bps) {
    const p = bytesParts(bps);
    return { num: p.num, unit: p.unit + "/s" };
  }

  function tunnelSample(name) {
    const s = state.stats && state.stats.tunnels ? state.stats.tunnels[name] : null;
    return s || { up: 0, down: 0, upSpeed: 0, downSpeed: 0 };
  }

  // pushSpark 记录全局速率采样，供迷你趋势图使用（去抖，避免高频刷新刷屏）。
  // ts 与数值一一对应，供悬停提示显示该采样点的时刻。
  function pushSpark(t) {
    const now = Date.now();
    if (now - state.sparkAt < 2500) return;
    state.sparkAt = now;
    state.spark.down.push(Number(t.downSpeed) || 0);
    state.spark.up.push(Number(t.upSpeed) || 0);
    state.spark.ts.push(now);
    if (state.spark.down.length > 48) {
      state.spark.down.shift();
      state.spark.up.shift();
      state.spark.ts.shift();
    }
  }

  // renderTraffic 渲染概览面板右侧的「全局网速与流量」部分。
  function renderTraffic() {
    const box = $("traffic-body");
    if (!box) return;
    const t = (state.stats && state.stats.total) || { up: 0, down: 0, upSpeed: 0, downSpeed: 0 };
    pushSpark(t);
    const runningCount = (state.overview && state.overview.runningCount) || 0;
    const hint = $("traffic-hint");
    if (hint) {
      hint.textContent = runningCount > 0 ? I18N.t("overview.trafficRunning") : I18N.t("overview.trafficIdle");
    }
    box.replaceChildren(
      trafficChart("down", I18N.t("common.download"), t.downSpeed, t.down, state.spark.down, state.spark.ts),
      trafficChart("up", I18N.t("common.upload"), t.upSpeed, t.up, state.spark.up, state.spark.ts),
    );
  }

  function trafficChart(kind, label, speed, total, hist, ts) {
    const parts = fmtRateParts(speed);
    return el("div", { class: "chart " + kind }, [
      el("div", { class: "chart-top" }, [
        el("div", {}, [
          el("div", { class: "label" }, [el("i", { style: "background:var(--" + kind + ")" }), el("span", { text: label })]),
          el("div", { class: "rate" }, [document.createTextNode(parts.num), el("u", { text: parts.unit })]),
        ]),
        el("div", { class: "total", text: fmt(I18N.t("traffic.total"), fmtBytes(total)) }),
      ]),
      sparkSvg(kind, hist, ts),
    ]);
  }

  // sparkSvg 用 SVG 折线 + 面积绘制迷你趋势（viewBox 归一化，随容器拉伸）。
  // 附带悬停提示：光标移到曲线上任意位置，显示该采样点的速率。
  function sparkSvg(kind, hist, ts) {
    const W = 100, H = 50;
    let vals = (hist && hist.length >= 2) ? hist.slice() : [0, 0];
    const n = vals.length;
    const max = Math.max.apply(null, vals.concat([1]));
    const step = n > 1 ? W / (n - 1) : 0;
    const pts = vals.map((v, i) => {
      const x = n > 1 ? i * step : W / 2;
      const y = H - 3 - (v / max) * (H - 6);
      return x.toFixed(2) + "," + y.toFixed(2);
    });
    const line = pts.join(" ");
    const area = "0," + H + " " + line + " " + W + "," + H;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "spark " + kind);
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("preserveAspectRatio", "none");
    svg.innerHTML = '<polygon class="area" points="' + area + '"/><polyline class="line" points="' + line + '"/>';

    const wrap = el("div", { class: "spark-wrap" });
    const cursor = el("div", { class: "spark-cursor hidden" });
    const tip = el("div", { class: "spark-tip hidden" });
    wrap.appendChild(svg);
    wrap.appendChild(cursor);
    wrap.appendChild(tip);

    // 悬停：按光标横坐标定位采样点，显示该点的速率并画出指示线。
    wrap.addEventListener("mousemove", (ev) => {
      const r = svg.getBoundingClientRect();
      if (!r.width || n < 2) return;
      const ratio = Math.min(1, Math.max(0, (ev.clientX - r.left) / r.width));
      const idx = Math.min(n - 1, Math.max(0, Math.round(ratio * (n - 1))));
      const x = (idx / (n - 1)) * r.width;
      const wr = wrap.getBoundingClientRect();
      cursor.style.left = x + "px";
      tip.textContent = sparkTipText(vals[idx], ts && ts[idx]);
      tip.style.left = (ev.clientX - wr.left) + "px";
      tip.style.top = Math.max(0, ev.clientY - wr.top - 26) + "px";
      cursor.classList.remove("hidden");
      tip.classList.remove("hidden");
    });
    wrap.addEventListener("mouseleave", () => {
      cursor.classList.add("hidden");
      tip.classList.add("hidden");
    });
    return wrap;
  }

  // sparkTipText 是趋势图悬停提示的文案：采样时刻 + 该点速率。
  function sparkTipText(v, ts) {
    const rate = fmtRate(v);
    if (!ts) return rate;
    const d = new Date(ts);
    const hh = String(d.getHours()).padStart(2, "0");
    const mm = String(d.getMinutes()).padStart(2, "0");
    const ss = String(d.getSeconds()).padStart(2, "0");
    return hh + ":" + mm + ":" + ss + " · " + rate;
  }

  /* ------------------------------ 隧道表 ------------------------------ */

  function matchFilter(t) {
    if (state.filter === "running") return !!t.running;
    if (state.filter === "stopped") return !t.running && !!t.enabled;
    if (state.filter === "off") return !t.enabled;
    return true;
  }

  function renderTunnels() {
    const body = $("tunnels");
    body.replaceChildren();
    const all = state.tunnels || [];
    const list = all.filter(matchFilter);

    const empty = $("empty");
    const tbl = document.querySelector(".split .panel .tbl-wrap");
    if (empty) empty.classList.toggle("hidden", all.length > 0);
    if (tbl) tbl.classList.toggle("hidden", all.length === 0);

    if (!list.length) {
      body.appendChild(el("tr", {}, [
        el("td", { class: "tblank", colspan: "6", text: all.length ? I18N.t("tunnels.noMatch") : I18N.t("tunnels.empty.title") }),
      ]));
    } else {
      list.forEach((t) => body.appendChild(tunnelRow(t)));
    }
    renderDetail();
  }

  function tunnelRow(t) {
    const tr = el("tr", {
      class: (state.selected === t.name ? "is-sel " : "") + (t.enabled ? "" : "is-off"),
    });
    tr.addEventListener("click", () => openDetail(t.name));

    tr.appendChild(el("td", {}, [
      el("div", { class: "tname" }, [
        el("span", { class: "dot" + (t.running ? " on" : "") }),
        el("b", { text: t.name }),
        t.enabled ? null : el("span", { class: "off-tag", text: I18N.t("common.disabled") }),
      ]),
    ]));

    tr.appendChild(el("td", {}, [
      el("div", { class: "endpoint", text: endpointText(t) }),
      t.peerIP ? el("div", { class: "peer" }, [
        el("span", { class: "fam", text: t.peerIP.indexOf(":") >= 0 ? "IPv6" : "IPv4" }),
        el("span", { text: t.peerIP }),
      ]) : null,
    ]));

    tr.appendChild(el("td", {}, [
      el("div", { class: "tun" }, [
        document.createTextNode(t.tunName || "—"),
        el("em", { text: (t.tunAddress || "") + " · MTU " + (t.tunMtu || "—") }),
      ]),
    ]));

    const s = tunnelSample(t.name);
    tr.appendChild(el("td", { class: "num" }, [rateEl("down", s.downSpeed, s.down)]));
    tr.appendChild(el("td", { class: "num" }, [rateEl("up", s.upSpeed, s.up)]));
    tr.appendChild(el("td", { class: "num" }, [rowActions(t)]));
    return tr;
  }

  function rateEl(kind, speed, total) {
    return el("span", { class: "rate " + kind + (speed > 0 ? "" : " zero") }, [
      document.createTextNode(fmtRate(speed)),
      el("span", { class: "acc", text: fmt(I18N.t("traffic.total"), fmtBytes(total)) }),
    ]);
  }

  function rowActions(t) {
    const wrap = el("div", { class: "rowacts" });
    wrap.addEventListener("click", (ev) => ev.stopPropagation());
    const busyOp = state.busy[t.name];
    if (busyOp) {
      wrap.appendChild(el("button", { class: "btn btn-sm", disabled: "disabled", text: busyLabel(busyOp) }));
      return wrap;
    }
    // 行内只保留运行控制与编辑；日志/删除放在详情抽屉里
    actionDefs(t, "row").forEach((a) => wrap.appendChild(el("button", {
      class: "btn-mini" + (a.tone ? " " + a.tone : ""),
      text: a.label,
      title: a.label,
      onclick: a.run,
    })));
    // 详情放在最右侧，与左侧的隧道名形成对照
    const open = state.selected === t.name;
    wrap.appendChild(el("button", {
      class: "btn-mini" + (open ? " is-on" : ""),
      text: I18N.t("tunnels.detail"),
      title: I18N.t("tunnels.detail.title"),
      onclick: () => openDetail(t.name),
    }));
    return wrap;
  }

  // actionDefs 汇总单条隧道可用的操作。
  // scope="row" 时给运行控制与编辑（编辑仅在隧道未运行时出现）；
  // 其余（日志/删除）只在详情抽屉里出现。tone 为语义配色。
  function actionDefs(t, scope) {
    const acts = [];
    if (t.running) {
      acts.push({ id: "stop", label: I18N.t("act.stop"), tone: "btn-warn", run: () => runAction("stop", [t.name], fmt(I18N.t("act.stopped"), t.name)) });
      acts.push({ id: "restart", label: I18N.t("act.restart"), tone: "btn-info", run: () => runAction("restart", [t.name], fmt(I18N.t("act.restarted"), t.name)) });
    } else {
      acts.push({ id: "start", label: I18N.t("act.start"), tone: "btn-primary", run: () => runAction("start", [t.name], fmt(I18N.t("act.started"), t.name)) });
    }
    if (scope === "row") {
      if (!t.running) acts.push({ id: "edit", label: I18N.t("act.edit"), run: () => openEdit(t) });
      return acts;
    }
    acts.push({ id: "logs", label: I18N.t("common.logs"), run: () => openLogs(t.name) });
    acts.push({ id: "del", label: I18N.t("act.delete"), tone: "btn-danger", run: () => { deleteTunnelByName(t.name).catch(() => {}); } });
    return acts;
  }

  function switchEl(checked, onChange, label) {
    const input = el("input", { type: "checkbox" });
    if (label) input.setAttribute("aria-label", label);
    input.checked = !!checked;
    input.addEventListener("change", () => onChange(input.checked));
    const wrap = el("label", { class: "switch" }, [input, el("span", { class: "slider" })]);
    // 切换启用状态时不要连带选中该行。
    wrap.addEventListener("click", (ev) => ev.stopPropagation());
    return wrap;
  }

  // openDetail 打开右侧详情抽屉：与「运行日志」同款，全高从右边滑出。
  function openDetail(name) {
    state.selected = name;
    renderTunnels();   // 内部会调用 renderDetail 填充抽屉内容
    openDialog("drawer-detail");
  }

  // endpointText 是 user@host:port 的统一格式（表格与检视器共用）。
  function endpointText(t) {
    return (t.sshUser || "") + "@" + (t.sshHost || "") + ":" + t.sshPort;
  }

  // forwardText 是端口转发描述的统一格式（检视器与编辑区共用）。
  function forwardText(f) {
    return (f.direction === "local" ? "L " : "R ") + (f.bindAddr || "*") + ":" + f.bindPort +
      " → " + f.targetHost + ":" + f.targetPort;
  }

  /* ------------------------------ 详情抽屉 ----------------------------- */

  // renderDetail 填充右侧详情抽屉：操作按钮排在顶部，正文为键值表 + 路由 + 转发。
  function renderDetail() {
    const box = $("detail-body");
    const acts = $("detail-actions");
    const title = $("detail-title");
    const status = $("detail-status");
    if (!box || !acts) return;
    const t = (state.tunnels || []).find((x) => x.name === state.selected);
    if (!t) {
      box.replaceChildren();
      acts.replaceChildren();
      return;
    }

    title.textContent = t.name;
    status.textContent = (t.running ? I18N.t("common.running") : I18N.t("common.stopped")) +
      (t.enabled ? "" : " · " + I18N.t("common.disabledMarked"));
    status.className = "pill " + (t.running ? "pill-ok" : "pill-muted");

    // 顶部操作按钮（与日志抽屉一致：动作放在标题栏右侧）
    // 先清空再渲染：renderDetail 会被轮询反复调用，否则按钮会不断累积。
    acts.replaceChildren();
    const busyOp = state.busy[t.name];
    if (busyOp) {
      acts.appendChild(el("button", { class: "btn btn-sm", disabled: "disabled", text: busyLabel(busyOp) }));
    } else {
      actionDefs(t).forEach((a) => {
        const cls = "btn btn-sm" + (a.tone ? " " + a.tone : "");
        acts.appendChild(el("button", { class: cls, text: a.label, onclick: a.run }));
      });
    }

    const s = tunnelSample(t.name);
    const body = el("div", { class: "det-body" }, [
      // 启用/停用开关：随详情一起放在抽屉里
      el("label", { class: "switch-row" }, [
        el("span", { class: "switch-row-label", text: I18N.t("tunnel.enableLabel") }),
        switchEl(t.enabled, (v) => toggleEnabled(t, v), fmt(I18N.t("common.enable"), t.name)),
      ]),
      el("div", { class: "sec-title", text: I18N.t("tunnel.conn") }),
      el("dl", { class: "kv" }, [
        el("dt", { text: "SSH" }), el("dd", { text: endpointText(t) }),
        el("dt", { text: I18N.t("tunnel.peerIP") }), el("dd", {}, t.peerIP
          ? [el("span", { class: "fam-tag", text: t.peerIP.indexOf(":") >= 0 ? "IPv6" : "IPv4" }),
             el("span", { text: " " + t.peerIP })]
          : [document.createTextNode("—")]),
        el("dt", { text: I18N.t("tunnel.auth") }), el("dd", { text: t.sshAuth === "password"
          ? I18N.t("common.password")
          : fmt(I18N.t("tunnel.authKey"), t.sshKeyFile || I18N.t("common.unspecified")) }),
        el("dt", { text: "TUN" }), el("dd", { text: (t.tunName || "—") + " · " + (t.tunAddress || "") }),
        el("dt", { text: "MTU" }), el("dd", { text: String(t.tunMtu || "—") }),
        el("dt", { text: I18N.t("tunnel.fingerprint") }), el("dd", { text: t.sshHostKey === "none" ? I18N.t("tunnel.noVerify") : (t.sshHostKey || "accept-new") }),
      ]),
      el("div", { class: "sec-title", text: I18N.t("tunnel.traffic") }),
      el("div", { class: "stat-row" }, [
        statCell("down", I18N.t("common.download"), s.downSpeed, s.down),
        statCell("up", I18N.t("common.upload"), s.upSpeed, s.up),
      ]),
    ]);
    body.appendChild(el("div", { class: "sec-title", text: I18N.t("common.routes") }));
    body.appendChild(chipsFor(t.routes, (r) => ({
      text: r.cidr + (r.kind === "bypass" ? " ↷" : ""),
      cls: r.kind === "bypass" ? "bypass" : "",
    }), I18N.t("common.noRoutes")));
    body.appendChild(el("div", { class: "sec-title", text: I18N.t("common.forwards") }));
    body.appendChild(chipsFor(t.forwards, (f) => ({
      text: forwardText(f),
      cls: f.direction === "remote" ? "remote" : "",
    }), I18N.t("common.noForwards")));

    box.replaceChildren(body);
  }

  // statCell 是详情抽屉里的单个流量格（速率 + 累计）。
  function statCell(kind, label, speed, total) {
    return el("div", { class: "stat-cell" }, [
      el("div", { class: "k" }, [
        el("i", { style: "background:var(--" + kind + ")" }),
        el("span", { text: label }),
      ]),
      el("div", { class: "v " + kind, text: fmtRate(speed) }),
      el("div", { class: "t", text: fmt(I18N.t("traffic.total"), fmtBytes(total)) }),
    ]);
  }

  function chipsFor(items, mapFn, emptyText) {
    const box = el("div", { class: "chips" });
    if (!items || !items.length) {
      box.appendChild(el("span", { class: "chip mute", text: emptyText }));
      return box;
    }
    items.forEach((it) => {
      const m = mapFn(it);
      box.appendChild(el("span", { class: "chip" + (m.cls ? " " + m.cls : ""), text: m.text }));
    });
    return box;
  }

  /* ---------------------------- 顶部动作 ----------------------------- */

  function busyLabel(op) {
    if (op === "start") return I18N.t("act.starting");
    if (op === "stop") return I18N.t("act.stopping");
    return I18N.t("act.restarting");
  }

  // renderToolbar 依据批量操作状态更新底部按钮文案与可用性。
  function renderToolbar() {
    const op = state.globalBusy;
    const items = [
      ["btn-start", "start", I18N.t("act.startAll"), I18N.t("act.starting")],
      ["btn-stop", "stop", I18N.t("act.stopAll"), I18N.t("act.stopping")],
      ["btn-restart", "restart", I18N.t("act.restartAll"), I18N.t("act.restarting")],
    ];
    items.forEach(([id, key, normal, loading]) => {
      const btn = $(id);
      if (!btn) return;
      btn.textContent = op === key ? loading : normal;
      btn.disabled = !!op;
    });
  }

  function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
  }

  // targetsFor 推断本次操作会影响的隧道名（用于驱动按钮 loading 与等待收敛）。
  function targetsFor(op, names) {
    const list = state.tunnels || [];
    if (names && names.length) return names.slice();
    if (op === "stop") return list.filter((t) => t.running).map((t) => t.name);
    if (op === "restart") return list.filter((t) => t.enabled).map((t) => t.name);
    return list.filter((t) => t.enabled && !t.running).map((t) => t.name); // start
  }

  function setBusy(names, op, global) {
    (names || []).forEach((n) => { state.busy[n] = op; });
    if (global) state.globalBusy = op;
    renderTunnels();
    renderToolbar();
  }

  function clearBusy(names, global) {
    (names || []).forEach((n) => { delete state.busy[n]; });
    if (global) state.globalBusy = null;
    renderTunnels();
    renderToolbar();
  }

  // waitSettled 反复刷新，直到目标隧道的运行状态达到期望（或整体已收敛/超时），
  // 返回是否全部达到期望。用于在启停较慢时给出「启动中/停止中/重启中」的持续反馈。
  async function waitSettled(op, targets) {
    if (!targets || !targets.length) {
      await sleep(500);
      return true;
    }
    const want = op !== "stop"; // 期望的 running 值
    const deadline = Date.now() + 15000;
    let lastKey = null, stable = 0, progressed = false;
    for (;;) {
      await refresh();
      const map = {};
      (state.tunnels || []).forEach((t) => { map[t.name] = !!t.running; });
      if (targets.every((n) => map[n] === want)) return true;
      if (targets.some((n) => map[n] === want)) progressed = true;
      const key = targets.map((n) => (map[n] ? "1" : "0")).join("");
      if (key === lastKey) stable++; else { stable = 0; lastKey = key; }
      // 已有隧道达到期望、或会话已就绪（state 已落盘）而状态仍持续不变时，
      // 认为剩余隧道已判定（多为启动失败），提前结束等待。
      if (stable >= 5 && (progressed || (state.overview && state.overview.running))) return false;
      if (Date.now() > deadline) return false;
      await sleep(700);
    }
  }

  async function runAction(op, names, okMsg) {
    const global = !(names && names.length);
    const targets = targetsFor(op, names);
    setBusy(targets, op, global);
    try {
      await api("POST", "/api/actions/" + op, { names: names || [] });
    } catch (e) {
      if (e && e.needAdmin) {
        clearBusy(targets, global);
        openElevatePrompt(e.action, e.names);
        return;
      }
      toast(e.message, "err");
      clearBusy(targets, global);
      await refresh();
      if (op !== "stop") await checkCredFailure(targets);
      return;
    }
    // 以实际运行状态为准给出反馈：达到期望才算成功，否则提示未生效（多为启动失败）。
    const settled = await waitSettled(op, targets);
    clearBusy(targets, global);
    await refresh();
    if (settled) {
      if (okMsg) toast(okMsg, "ok");
    } else {
      toast(I18N.t("act.notApplied"), "err");
      // 未进入运行态时检查是否为凭据类失败，是则弹出凭据修正窗口。
      if (op !== "stop") await checkCredFailure(targets);
    }
  }

  async function toggleEnabled(tunnel, enabled) {
    try {
      await api("POST", "/api/tunnels/" + encodeURIComponent(tunnel.uid || tunnel.name) + "/enabled", { enabled });
      tunnel.enabled = enabled;
      toast(fmt(enabled ? I18N.t("act.enabled") : I18N.t("act.disabled"), tunnel.name), "ok");
      renderTunnels();
    } catch (e) {
      toast(e.message, "err");
      refresh();
    }
  }

  /* ------------------------------ 刷新 ------------------------------- */

  async function refresh() {
    if (state.elevating || state.refreshing) return;
    state.refreshing = true;
    try {
      const [ov, ts, st] = await Promise.all([
        api("GET", "/api/overview"),
        api("GET", "/api/tunnels"),
        api("GET", "/api/stats").catch(() => null),
      ]);
      state.overview = ov;
      state.tunnels = ts || [];
      state.stats = st;
      renderOverview();
      renderTraffic();
      renderTunnels();
      renderLogFilter();
      renderToolbar();
    } catch (e) {
      // 401 已由 api() 转入登录流程；其余错误记录下来便于排查，但不打断轮询。
      if (e && e.message !== I18N.t("error.unauthorized")) console.warn("刷新失败:", e.message);
    } finally {
      state.refreshing = false;
    }
  }

  function scheduleRefresh(delay) {
    setTimeout(refresh, delay || 200);
  }

  /* ---------------------------- 编辑弹窗 ----------------------------- */

  // nameError 校验隧道名，返回错误文案（空串表示合法）。
  // 规则与后端 validateTunnelName 一致：沿用文件名的字符约束——
  // 不能含空格、控制字符与 <>:"/\|?* ，不能以 . 结尾，不得占用保留名 all；
  // 其余符号（- _ # @ ( ) + % 等）与中英文、数字一律放行。
  function nameError(name) {
    const n = (name || "").trim();
    if (!n) return I18N.t("tunnel.nameEmpty");
    if (Array.from(n).length > 32) return I18N.t("tunnel.nameTooLong");
    if (n.toLowerCase() === "all") return I18N.t("tunnel.nameReserved");
    if (/\s/.test(n)) return I18N.t("tunnel.nameSpace");
    const bad = n.match(/[\u0000-\u001f\u007f<>:"\/\\|?*]/);
    if (bad) return fmt(I18N.t("tunnel.nameBadChar"), bad[0]);
    if (n.endsWith(".")) return I18N.t("tunnel.nameDot");
    return "";
  }

  // 生成可用的默认 TUN 网卡名与地址：在同名/同地址均未被占用中取最小序号，
  // 因此新增隧道（无论此前删过哪几条）都能拿到不冲突的值。
  function freeTunDefaults() {
    const usedNames = new Set((state.tunnels || []).map((t) => t.tunName).filter(Boolean));
    const usedAddrs = new Set((state.tunnels || []).map((t) => t.tunAddress).filter(Boolean));
    for (let n = 1; n <= 512; n++) {
      const name = "sshtun" + n;
      const address = "198." + (18 + Math.floor((n - 1) / 256)) + "." + ((n - 1) % 256) + ".1/30";
      if (!usedNames.has(name) && !usedAddrs.has(address)) {
        return { name, address };
      }
    }
    return { name: "sshtun1", address: "198.18.0.1/30" };
  }

  function suggestDefaults() {
    const free = freeTunDefaults();
    return {
      sshPort: 22, sshUser: "root", sshAuth: "key", sshHostKey: "accept-new",
      tunName: free.name, tunAddress: free.address, tunMtu: 1500,
    };
  }

  function openEdit(t) {
    const isNew = !t;
    const d = isNew ? suggestDefaults() : t;
    state.editing = {
      isNew: isNew,
      base: d,
      routes: (t && t.routes ? t.routes.slice() : []),
      forwards: (t && t.forwards ? t.forwards.slice() : []),
    };

    $("edit-title").textContent = isNew ? I18N.t("tunnel.new") : fmt(I18N.t("tunnel.editTitle"), t.name);
    const f = $("form-tunnel");
    // 隧道名可再次编辑：保存时按 UID 定位记录，改名不影响路由/转发等关联数据。
    f.elements.name.value = isNew ? "" : t.name;
    f.elements.ssh_host.value = d.sshHost || "";
    f.elements.ssh_port.value = d.sshPort || 22;
    f.elements.ssh_user.value = d.sshUser || "root";
    f.elements.ssh_auth.value = d.sshAuth || "key";
    f.elements.ssh_key_file.value = d.sshKeyFile || "";
    f.elements.password.value = "";
    f.elements.password.placeholder = t && t.hasPassword ? I18N.t("common.passwordSet") : I18N.t("settings.web.password.hint");
    f.elements.ssh_host_key.value = d.sshHostKey || "accept-new";
    f.elements.tun_name.value = d.tunName || "";
    f.elements.tun_address.value = d.tunAddress || "";
    f.elements.tun_mtu.value = d.tunMtu || 1500;

    // 记住打开时的连接地址：地址一变，后端会作废已存的密码，这里同步提示。
    state.editAddr = { host: f.elements.ssh_host.value.trim(), port: String(f.elements.ssh_port.value || "") };
    $("pwd-invalidated").classList.add("hidden");

    $("btn-delete").classList.toggle("hidden", isNew);
    $("edit-sub").textContent = isNew ? I18N.t("tunnel.sub.new") : I18N.t("tunnel.sub.edit");
    renderEditRoutes();
    renderEditForwards();
    syncAuthFields(f);
    openDialog("modal-edit", isNew ? "input[name=name]" : "input[name=ssh_host]");
  }

  // syncAuthFields 按认证方式显示对应凭据字段：私钥显示私钥文件，密码显示密码框。
  function syncAuthFields(f) {
    const isPwd = f.elements.ssh_auth.value === "password";
    f.querySelectorAll(".auth-key").forEach((x) => x.classList.toggle("hidden", isPwd));
    f.querySelectorAll(".auth-pwd").forEach((x) => x.classList.toggle("hidden", !isPwd));
  }

  // syncAddrChanged 检测连接地址是否被改动：后端会在地址变化时作废已存的密码，
  // 这里提前提示用户「需重新输入密码」，避免保存后隧道起不来才发现。
  function syncAddrChanged(f) {
    const hint = $("pwd-invalidated");
    if (!hint) return;
    const base = state.editAddr;
    const changed = !!base && (f.elements.ssh_host.value.trim() !== base.host ||
      String(f.elements.ssh_port.value || "") !== base.port);
    hint.classList.toggle("hidden", !changed);
  }

  function renderEditRoutes() {
    const box = $("routes-list");
    box.replaceChildren();
    const rs = state.editing.routes;
    if (!rs.length) { box.appendChild(el("span", { class: "chip mute", text: I18N.t("common.noRoutes") })); return; }
    rs.forEach((r, i) => {
      box.appendChild(el("span", { class: "chip-edit" }, [
        document.createTextNode(r.cidr + (r.kind === "bypass" ? " (bypass)" : "")),
        el("button", { type: "button", text: "✕", title: I18N.t("common.remove"), onclick: () => { rs.splice(i, 1); renderEditRoutes(); } }),
      ]));
    });
  }

  function renderEditForwards() {
    const box = $("forwards-list");
    box.replaceChildren();
    const fs = state.editing.forwards;
    if (!fs.length) { box.appendChild(el("span", { class: "chip mute", text: I18N.t("common.noForwards") })); return; }
    fs.forEach((fw, i) => {
      box.appendChild(el("span", { class: "chip-edit" }, [
        document.createTextNode(describeForward(fw)),
        el("button", { type: "button", text: "✕", title: I18N.t("common.remove"), onclick: () => { fs.splice(i, 1); renderEditForwards(); } }),
      ]));
    });
  }

  function describeForward(f) {
    return forwardText(f);
  }

  async function saveTunnel() {
    const f = $("form-tunnel");
    const e = state.editing;
    const payload = {
      // UID 定位隧道：名字可改，UID 不变，保存时据此更新同一条记录
      uid: e && e.base ? (e.base.uid || "") : "",
      name: f.elements.name.value.trim(),
      // 启用状态不在编辑栏修改，沿用隧道当前值（新建时默认启用）
      enabled: e && e.base ? e.base.enabled !== false : true,
      sshHost: f.elements.ssh_host.value.trim(),
      sshPort: parseInt(f.elements.ssh_port.value, 10) || 0,
      sshUser: f.elements.ssh_user.value.trim(),
      sshAuth: f.elements.ssh_auth.value,
      sshKeyFile: f.elements.ssh_key_file.value.trim(),
      sshHostKey: f.elements.ssh_host_key.value,
      password: f.elements.password.value,
      tunName: f.elements.tun_name.value.trim(),
      tunAddress: f.elements.tun_address.value.trim(),
      tunMtu: parseInt(f.elements.tun_mtu.value, 10) || 0,
    };
    const bad = nameError(payload.name);
    if (bad) {
      toast(bad, "err");
      f.elements.name.focus();
      return;
    }
    if (!payload.sshUser) { toast(I18N.t("tunnel.userEmpty"), "err"); f.elements.ssh_user.focus(); return; }
    if (payload.sshAuth === "key" && !payload.sshKeyFile) { toast(I18N.t("tunnel.keyRequired"), "err"); f.elements.ssh_key_file.focus(); return; }

    let saved = null;
    await act(async () => {
      saved = await api("POST", "/api/tunnels", payload);
      const uid = (saved && saved.uid) || payload.uid;
      if (!e.isNew) {
        await syncRoutes(uid, e.base.routes || [], e.routes);
        await syncForwards(uid, e.base.forwards || [], e.forwards);
      } else {
        for (const r of e.routes) await addRoute(uid, r);
        for (const fw of e.forwards) await addForward(uid, fw);
      }
    }, fmt(I18N.t("tunnel.saved"), payload.name));

    closeDialog($("modal-edit"));
    refresh();
  }

  async function syncRoutes(uid, before, after) {
    const key = (r) => r.cidr;
    const beforeMap = new Map(before.map((r) => [key(r), r]));
    const afterMap = new Map(after.map((r) => [key(r), r]));
    for (const [k, r] of afterMap) {
      if (!beforeMap.has(k)) await addRoute(uid, r);
      else if (beforeMap.get(k).kind !== r.kind) {
        await delRoute(uid, k);
        await addRoute(uid, r);
      }
    }
    for (const [k] of beforeMap) if (!afterMap.has(k)) await delRoute(uid, k);
  }

  async function syncForwards(uid, before, after) {
    const key = (f) => f.direction + ":" + f.bindPort;
    const beforeMap = new Map(before.map((f) => [key(f), f]));
    const afterMap = new Map(after.map((f) => [key(f), f]));
    for (const [k, fw] of afterMap) {
      if (!beforeMap.has(k)) await addForward(uid, fw);
      else {
        const b = beforeMap.get(k);
        if (b.bindAddr !== fw.bindAddr || b.targetHost !== fw.targetHost || b.targetPort !== fw.targetPort || b.enabled !== fw.enabled) {
          await delForward(uid, b);
          await addForward(uid, fw);
        }
      }
    }
    for (const [k, fw] of beforeMap) if (!afterMap.has(k)) await delForward(uid, fw);
  }

  function addRoute(uid, r) {
    return api("POST", "/api/tunnels/" + encodeURIComponent(uid) + "/routes?cidr=" +
      encodeURIComponent(r.cidr) + "&bypass=" + (r.kind === "bypass"));
  }
  function delRoute(uid, cidr) {
    return api("DELETE", "/api/tunnels/" + encodeURIComponent(uid) + "/routes?cidr=" + encodeURIComponent(cidr));
  }
  function addForward(uid, f) {
    return api("POST", "/api/tunnels/" + encodeURIComponent(uid) + "/forwards", {
      direction: f.direction, bindAddr: f.bindAddr, bindPort: f.bindPort,
      targetHost: f.targetHost, targetPort: f.targetPort, enabled: f.enabled !== false,
    });
  }
  function delForward(uid, f) {
    return api("DELETE", "/api/tunnels/" + encodeURIComponent(uid) + "/forwards?direction=" +
      encodeURIComponent(f.direction) + "&port=" + f.bindPort);
  }

  // deleteTunnelByName 删除指定隧道：二次确认后调用接口，成功返回 true。
  // 按 UID 删除，隧道改名后依然能删到正确的记录。
  async function deleteTunnelByName(name) {
    if (!confirm(fmt(I18N.t("tunnel.deleteConfirm"), name))) return false;
    const t = (state.tunnels || []).find((x) => x.name === name);
    const uid = t ? t.uid : name;
    await act(() => api("DELETE", "/api/tunnels/" + encodeURIComponent(uid)), fmt(I18N.t("tunnel.deleted"), name));
    if (state.selected === name) state.selected = "";
    refresh();
    return true;
  }

  async function deleteTunnel() {
    const e = state.editing;
    if (!e || e.isNew) return;
    const name = $("form-tunnel").name.value;
    if (!(await deleteTunnelByName(name))) return;
    closeDialog($("modal-edit"));
  }

  /* --------------------------- SSH 凭据修正 --------------------------- */

  // checkCredFailure 查询后端登记的启动失败；若目标隧道中存在凭据类失败
  // （用户名/密码/私钥错误或未填写），弹出凭据修正窗口让用户重填并自动保存。
  async function checkCredFailure(names) {
    let fails = null;
    try { fails = await api("GET", "/api/failures"); } catch (e) { return false; }
    if (!fails) return false;
    const list = (names && names.length) ? names : Object.keys(fails);
    for (const n of list) {
      const f = fails[n];
      if (f && f.kind === "auth") {
        openCredDialog(n, f);
        return true;
      }
    }
    return false;
  }

  // openCredDialog 展示凭据修正窗口：按隧道当前认证方式显示密码或私钥字段。
  function openCredDialog(name, failure) {
    const t = (state.tunnels || []).find((x) => x.name === name);
    if (!t) return;
    state.cred = { name: name };
    const isPwd = t.sshAuth === "password";
    const f = $("form-cred");
    $("cred-err").textContent = fmt(I18N.t("cred.failed"), name, firstLine(failure.message || I18N.t("cred.rejected")));
    f.elements.cred_user.value = t.sshUser || "";
    f.elements.cred_pass.value = "";
    f.elements.cred_key.value = t.sshKeyFile || "";
    f.elements.cred_keypass.value = "";
    // 密码认证只问密码；私钥认证只问私钥路径与口令。
    document.querySelectorAll("#form-cred .cred-pwd").forEach((x) => x.classList.toggle("hidden", !isPwd));
    document.querySelectorAll("#form-cred .cred-key").forEach((x) => x.classList.toggle("hidden", isPwd));
    $("btn-cred-save").disabled = false;
    openDialog("modal-cred", isPwd ? "input[name=cred_pass]" : "input[name=cred_key]");
  }

  // firstLine 只取错误信息首行，避免把整段提示塞进一行提示条。
  function firstLine(s) {
    return String(s || "").split("\n")[0].trim();
  }

  // saveCredRetry 保存新凭据（后端自动加密入库）并立即重试启动该隧道。
  async function saveCredRetry() {
    const cur = state.cred;
    if (!cur) return;
    const t = (state.tunnels || []).find((x) => x.name === cur.name);
    if (!t) { closeDialog($("modal-cred")); return; }

    const f = $("form-cred");
    const user = f.elements.cred_user.value.trim();
    if (!user) { toast(I18N.t("tunnel.userEmpty"), "err"); f.elements.cred_user.focus(); return; }
    const isPwd = t.sshAuth === "password";
    const pass = f.elements.cred_pass.value;
    const key = f.elements.cred_key.value.trim();
    if (isPwd && !pass) { toast(I18N.t("cred.enterPassword"), "err"); f.elements.cred_pass.focus(); return; }
    if (!isPwd && !key) { toast(I18N.t("cred.keyPathRequired"), "err"); f.elements.cred_key.focus(); return; }

    const btn = $("btn-cred-save");
    btn.disabled = true;
    btn.textContent = I18N.t("common.saving");
    try {
      const payload = {
        uid: t.uid || "", name: t.name, enabled: t.enabled,
        sshHost: t.sshHost, sshPort: t.sshPort, sshUser: user, sshAuth: t.sshAuth,
        sshKeyFile: key, sshHostKey: t.sshHostKey,
        password: isPwd ? pass : "",
        tunName: t.tunName, tunAddress: t.tunAddress, tunMtu: t.tunMtu,
      };
      if (!isPwd) payload.sshKeyPassphrase = f.elements.cred_keypass.value;
      await api("POST", "/api/tunnels", payload);
      toast(fmt(I18N.t("cred.saved"), t.name), "ok");
      closeDialog($("modal-cred"));
      // 用新凭据立即重试；若仍失败会再次弹出本窗口（含最新错误）。
      await runAction("start", [t.name], fmt(I18N.t("act.started"), t.name));
    } catch (e) {
      toast(e.message, "err");
    } finally {
      btn.disabled = false;
      btn.textContent = I18N.t("cred.save");
    }
  }

  /* ------------------------------ 日志 ------------------------------- */

  // renderLogFilter 填充日志抽屉的隧道筛选下拉：全部 + 各隧道。
  // 仅在隧道集合变化时重建，避免每次刷新都打断用户正在使用的下拉。
  function renderLogFilter() {
    const sel = $("log-tunnel");
    if (!sel) return;
    const names = (state.tunnels || []).map((t) => t.name);
    const key = names.join("\u0000");
    if (key === state.logFilterKey) return;
    state.logFilterKey = key;
    const cur = state.logTunnel || "";
    const opts = [el("option", { value: "", text: I18N.t("logs.allTunnels") })];
    names.forEach((n) => opts.push(el("option", { value: n, text: n })));
    sel.replaceChildren.apply(sel, opts);
    sel.value = cur;
  }

  // openLogs 打开日志抽屉；传入隧道名时仅显示该隧道的日志。
  async function openLogs(tunnelName) {
    state.logTunnel = tunnelName || "";
    renderLogFilter();
    openDialog("drawer-logs");
    await loadLogs();
    startLogTimer();
  }

  // 日志自动刷新相关的偏好保存在本地，刷新页面后仍然生效。
  const LOG_AUTO_KEY = "sshtun_log_auto";
  const LOG_INTERVAL_KEY = "sshtun_log_interval";

  // logIntervalMs 返回当前选择的自动刷新间隔（毫秒）。
  function logIntervalMs() {
    const sel = $("log-interval");
    const v = sel ? parseInt(sel.value, 10) : 0;
    return v > 0 ? v : 5000;
  }

  // loadLogPrefs 恢复上次的自动刷新开关与间隔。
  function loadLogPrefs() {
    try {
      const iv = parseInt(localStorage.getItem(LOG_INTERVAL_KEY), 10);
      const sel = $("log-interval");
      if (iv > 0 && sel) sel.value = String(iv);
      if (localStorage.getItem(LOG_AUTO_KEY) === "1") setLogAuto(true);
    } catch (e) { /* 忽略存储异常 */ }
  }

  // setLogAuto 开启/关闭日志自动刷新，并同步按钮状态与本地偏好。
  function setLogAuto(on) {
    state.logAuto = !!on;
    const b = $("btn-log-auto");
    if (b) {
      b.classList.toggle("is-on", state.logAuto);
      b.setAttribute("aria-pressed", state.logAuto ? "true" : "false");
      b.textContent = state.logAuto ? I18N.t("logs.autoOn") : I18N.t("logs.auto");
    }
    try { localStorage.setItem(LOG_AUTO_KEY, state.logAuto ? "1" : "0"); } catch (e) { /* 忽略 */ }
    startLogTimer();
  }

  // startLogTimer 按当前间隔启动自动刷新（已开启时）；重复调用会先清掉旧定时器。
  // 抽屉未打开时不轮询，避免后台无谓地拉取日志。
  function startLogTimer() {
    stopLogTimer();
    if (!state.logAuto) return;
    const d = $("drawer-logs");
    if (!d || d.classList.contains("hidden")) return;
    state.logTimer = setInterval(() => { loadLogs().catch(() => {}); }, logIntervalMs());
  }

  // stopLogTimer 停止自动刷新（抽屉关闭时调用，保留开关状态）。
  function stopLogTimer() {
    if (state.logTimer) {
      clearInterval(state.logTimer);
      state.logTimer = null;
    }
  }

  async function loadLogs() {
    const title = $("logs-title");
    if (title) title.textContent = state.logTunnel ? fmt(I18N.t("logs.titleFor"), state.logTunnel) : I18N.t("logs.title");
    const lines = parseInt($("log-lines").value, 10) || 300;
    const box = $("log-content");
    // 自动刷新时不要反复清空成「加载中…」，否则内容会闪烁。
    if (!box.textContent.trim()) box.textContent = I18N.t("logs.loading");
    try {
      let q = "/api/logs?lines=" + lines;
      if (state.logTunnel) q += "&tunnel=" + encodeURIComponent(state.logTunnel);
      const d = await api("GET", q);
      box.textContent = d.note ? d.note : (d.path ? "# " + d.path + "\n\n" + d.content : d.content || I18N.t("logs.empty"));
      // 始终跳到最新一条，便于观察刚产生的日志。
      box.scrollTop = box.scrollHeight;
    } catch (e) {
      box.textContent = fmt(I18N.t("logs.readFailed"), e.message);
    }
  }

  /* ------------------------------ 设置 ------------------------------- */

  // openSettings 打开设置弹窗并回填当前基础配置。
  async function openSettings() {
    const f = $("form-settings");
    try {
      const s = await api("GET", "/api/settings");
      f.elements.logLevel.value = s.logLevel || "info";
      f.elements.logDir.value = s.logDir || "";
      f.elements.logConsole.value = s.logConsole || "auto";
      f.elements.connectTimeout.value = s.connectTimeout || 15;
      f.elements.keepalive.value = s.keepalive || 0;
      f.elements.webHostname.value = s.webHostname || "127.0.0.1";
      f.elements.webPort.value = s.webPort || 0;
      f.elements.webUsername.value = s.webUsername || "admin";
      f.elements.webCORS.value = s.webCORS || "";
      f.elements.db.value = s.db || "";
      f.elements.tun2socks.value = s.tun2socks || "";
      f.elements.webLanguage.value = s.webLanguage || "auto";
      f.elements.webTheme.value = s.webTheme || "auto";
      f.elements.webPassword.value = "";
      f.elements.webPassword.placeholder = s.hasPassword ? I18N.t("common.passwordSet") : I18N.t("settings.web.password.unset");
      $("settings-path").textContent = s.path || "";
    } catch (e) {
      toast(fmt(I18N.t("settings.readFailed"), e.message), "err");
      return;
    }
    openDialog("modal-settings", "select[name=logLevel]");
  }

  // saveSettings 保存设置到配置文件；部分项需重启实例生效。
  async function saveSettings() {
    const f = $("form-settings");
    const payload = {
      db: f.elements.db.value.trim(),
      webHostname: f.elements.webHostname.value.trim(),
      webPort: parseInt(f.elements.webPort.value, 10) || 0,
      webCORS: f.elements.webCORS.value.trim(),
      webUsername: f.elements.webUsername.value.trim(),
      webPassword: f.elements.webPassword.value,
      webLanguage: f.elements.webLanguage.value,
      webTheme: f.elements.webTheme.value,
      tun2socks: f.elements.tun2socks.value.trim(),
      connectTimeout: parseInt(f.elements.connectTimeout.value, 10) || 0,
      keepalive: parseInt(f.elements.keepalive.value, 10) || 0,
      logLevel: f.elements.logLevel.value,
      logDir: f.elements.logDir.value.trim(),
      logConsole: f.elements.logConsole.value,
    };
    const btn = $("btn-settings-save");
    btn.disabled = true;
    btn.textContent = I18N.t("common.saving");
    try {
      const r = await api("POST", "/api/settings", payload);
      // 语言与主题立即生效，无需刷新页面。
      serverTheme = payload.webTheme || "auto";
      try { localStorage.setItem(THEME_KEY, serverTheme); } catch (e) { /* 忽略 */ }
      // 先切语言再刷主题：applyTheme 会写入主题按钮的动态标题，须排在 applyLang 之后。
      I18N.applyLang(I18N.resolveLang(payload.webLanguage));
      applyTheme();
      // 日志抽屉的自动刷新按钮文案由脚本维护，语言切换后同步一次。
      setLogAuto(state.logAuto);
      closeDialog($("modal-settings"));
      toast((r && r.note) || I18N.t("settings.saved"), "ok");
    } catch (e) {
      toast(e.message, "err");
    } finally {
      btn.disabled = false;
      btn.textContent = I18N.t("settings.save");
    }
  }

  /* ------------------------------ 对话框 ----------------------------- */

  // openDialog 显示弹窗/抽屉，记录打开前的焦点并把焦点移入对话框。
  function openDialog(id, focusSel) {
    state.lastFocus = document.activeElement;
    const d = $(id);
    if (!d) return;
    d.classList.remove("hidden");
    const target = focusSel
      ? d.querySelector(focusSel)
      : d.querySelector("input:not([disabled]), select, button");
    if (target) setTimeout(() => target.focus(), 0);
  }

  // closeDialog 隐藏对话框并把焦点归还给打开它的元素（键盘用户不会丢失位置）。
  function closeDialog(d) {
    if (!d) return;
    d.classList.add("hidden");
    // 关闭详情抽屉：清掉选中态，行内「详情」按钮不再保持高亮。
    if (d.id === "drawer-detail") {
      state.selected = "";
      renderTunnels();
    }
    // 关闭日志抽屉：停掉自动刷新定时器（开关状态保留，下次打开继续）。
    if (d.id === "drawer-logs") stopLogTimer();
    const prev = state.lastFocus;
    state.lastFocus = null;
    if (prev && document.contains(prev)) prev.focus();
  }

  /* ------------------------------ 绑定 ------------------------------- */

  function bind() {
    applyTheme();
    $("btn-theme").addEventListener("click", cycleTheme);

    $("btn-refresh").addEventListener("click", refresh);
    $("btn-logout").addEventListener("click", () => { doLogout().catch(() => {}); });
    $("form-login").addEventListener("submit", (ev) => { doLogin(ev).catch(() => {}); });

    $("btn-start").addEventListener("click", () => runAction("start", [], I18N.t("act.startedAll")));
    $("btn-stop").addEventListener("click", () => runAction("stop", [], I18N.t("act.stoppedAll")));
    $("btn-restart").addEventListener("click", () => runAction("restart", [], I18N.t("act.restartedAll")));

    $("btn-new").addEventListener("click", () => openEdit(null));
    $("btn-logs").addEventListener("click", () => openLogs(""));
    $("btn-settings").addEventListener("click", () => {
      openSettings().catch((e) => toast((e && e.message) || I18N.t("settings.openFailed"), "err"));
    });
    $("btn-settings-save").addEventListener("click", () => { saveSettings().catch(() => {}); });
    $("form-settings").addEventListener("submit", (ev) => { ev.preventDefault(); saveSettings().catch(() => {}); });
    $("form-tunnel").elements.ssh_auth.addEventListener("change", (ev) => {
      syncAuthFields(ev.target.form);
    });
    // 连接地址变化时提示「需重新输入密码」。
    ["ssh_host", "ssh_port"].forEach((n) => {
      const el = $("form-tunnel").elements[n];
      if (el) el.addEventListener("input", (ev) => { syncAddrChanged(ev.target.form); });
    });

    document.querySelectorAll("#tfilters button").forEach((b) => {
      b.addEventListener("click", () => {
        state.filter = b.getAttribute("data-f");
        document.querySelectorAll("#tfilters button").forEach((x) => {
          x.classList.toggle("is-on", x === b);
          x.setAttribute("aria-pressed", x === b ? "true" : "false");
        });
        renderTunnels();
      });
    });

    $("btn-log-reload").addEventListener("click", loadLogs);
    $("btn-log-auto").addEventListener("click", () => setLogAuto(!state.logAuto));
    $("log-interval").addEventListener("change", () => {
      try { localStorage.setItem(LOG_INTERVAL_KEY, $("log-interval").value); } catch (e) { /* 忽略 */ }
      startLogTimer();
    });
    loadLogPrefs();
    $("log-tunnel").addEventListener("change", () => {
      state.logTunnel = $("log-tunnel").value;
      loadLogs();
    });

    $("btn-elevate").addEventListener("click", () => openElevatePrompt("start", []));
    $("btn-elevate-go").addEventListener("click", () => { startElevation().catch(() => {}); });
    $("btn-elevate-retry").addEventListener("click", () => { startElevation().catch(() => {}); });
    $("btn-elevate-close").addEventListener("click", () => { hideElevate(); state.elevating = false; });

    $("btn-save").addEventListener("click", () => { saveTunnel().catch(() => {}); });
    $("btn-delete").addEventListener("click", () => { deleteTunnel().catch(() => {}); });

    $("btn-cred-save").addEventListener("click", () => { saveCredRetry().catch(() => {}); });
    $("form-cred").addEventListener("submit", (ev) => { ev.preventDefault(); saveCredRetry().catch(() => {}); });

    $("btn-add-route").addEventListener("click", () => {
      const cidr = $("route-cidr").value.trim();
      if (!cidr) { toast(I18N.t("tunnel.routeRequired"), "err"); return; }
      const kind = $("route-bypass").checked ? "bypass" : "tunnel";
      if (state.editing.routes.some((r) => r.cidr === cidr)) { toast(I18N.t("tunnel.routeExists"), "err"); return; }
      state.editing.routes.push({ cidr: cidr, kind: kind });
      $("route-cidr").value = "";
      $("route-bypass").checked = false;
      renderEditRoutes();
    });

    $("btn-add-fw").addEventListener("click", () => {
      const bp = parseInt($("fw-bind-port").value, 10);
      const tp = parseInt($("fw-port").value, 10);
      const host = $("fw-host").value.trim();
      if (!(bp >= 1 && bp <= 65535)) { toast(I18N.t("tunnel.fwPortInvalid"), "err"); return; }
      if (!host || !(tp >= 1 && tp <= 65535)) { toast(I18N.t("tunnel.fwTargetInvalid"), "err"); return; }
      const dir = $("fw-dir").value;
      if (state.editing.forwards.some((f) => f.direction === dir && f.bindPort === bp)) {
        toast(I18N.t("tunnel.fwExists"), "err"); return;
      }
      state.editing.forwards.push({
        direction: dir, bindAddr: $("fw-bind-host").value.trim(), bindPort: bp,
        targetHost: host, targetPort: tp, enabled: true,
      });
      $("fw-bind-port").value = ""; $("fw-host").value = ""; $("fw-port").value = ""; $("fw-bind-host").value = "";
      renderEditForwards();
    });

    document.querySelectorAll("[data-close]").forEach((b) =>
      b.addEventListener("click", () => closeDialog(b.closest(".modal"))));
    document.querySelectorAll(".modal").forEach((m) =>
      m.addEventListener("mousedown", (ev) => { if (ev.target === m) closeDialog(m); }));

    // Esc 关闭最上层的弹窗/抽屉（键盘可达性）。
    document.addEventListener("keydown", (ev) => {
      if (ev.key !== "Escape") return;
      const open = Array.from(document.querySelectorAll(".modal:not(.hidden)"));
      if (open.length) closeDialog(open[open.length - 1]);
    });

    $("form-tunnel").addEventListener("submit", (ev) => { ev.preventDefault(); saveTunnel().catch(() => {}); });
  }

  /* ------------------------------ 启动 ------------------------------- */

  function start() {
    watchSystemTheme();
    boot();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
