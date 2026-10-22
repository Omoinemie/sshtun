# sshtun

基于 **tun2socks + SSH** 的隧道代理工具。

> 源码仓库：<https://github.com/Omoinemie/sshtun>

把远端 SSH 服务器当作出网跳板：本机建立一条 SSH 连接，用 tun2socks 在本地创建虚拟网卡，
把指定的网段路由进去，流量经 SSH 加密后从远端发出。同时支持端口转发（`-L` / `-R`）。

提供三种使用方式：**命令行**、**Web 管理界面**、**Windows 图形程序**。

---

## 特性

- **三种前端，同一份数据**
  - `sshtun` 命令行：适合脚本与快速排查
  - `sshtun web`：内置 HTTP 服务，用浏览器管理隧道
  - `sshtun-gui`（仅 Windows）：内嵌 WebView2 的独立窗口
- **隧道配置存数据库**（SQLite），配置文件只保留基础设置；配置与隧道分离，便于多机同步
- **TUN 模式**：按网段分流，支持「走隧道」与「强制直连（bypass）」
- **SOCKS5 代理**：每条隧道一个独立代理，监听 `127.0.0.1`，端口由内核分配
- **端口转发**：本地转发（`-L`）与远程转发（`-R`）
- **凭据加密存储**：SSH 密码用 AES-256-GCM 加密后入库，密钥由「编译期种子 + 本机机器码」派生
- **主机密钥校验**：`accept-new`（首次自动信任）/ `strict`（必须已信任）/ `none`（不校验）
- **界面双语**：Web 界面中英双语，未配置语言时跟随浏览器系统语言
- **隧道进程隔离**：隧道跑在独立进程，Web 进程不持有明文凭据
- **跨实例互斥**：同一时刻同一条隧道只能被一个实例占用，避免 TUN 网卡被互删

---

## 快速开始

### 1. 准备 tun2socks

发行包内附带了下载脚本，运行即可（会解压到当前目录）：

```bash
# Linux / macOS
sh dl-tun2socks.sh
```

```bat
:: Windows
dl-tun2socks.bat
```

脚本会先比对本地版本，已是最新则跳过。Windows 版还会一并下载 `wintun.dll`。

### 2. 添加隧道

```bash
sshtun db tunnel add office \
  --host example.com --port 22 --user root \
  --auth password --password 'your-password' \
  --host-key accept-new \
  --tun-name sshtun0 --tun-address 198.18.0.1/30
```

### 3. 添加路由（哪些网段走隧道）

```bash
sshtun db route add office 192.168.31.0/24,10.0.0.0/8
```

逗号分隔可一次添加多条。`--bypass` 表示强制直连（不走隧道）。

### 4. 添加端口转发

```bash
# 本地 8080 -> 远端 10.0.0.5:80
sshtun db forward add office local 8080 10.0.0.5:80

# 一次添加多个端口，指向同一个目标
sshtun db forward add office local 8080,8081,8082 10.0.0.5:80
```

端口与目标数量相同时按顺序一一对应；只给一个目标时，该目标被所有端口共用。
本地转发默认只监听 `127.0.0.1`，需要对外暴露用 `--bind-addr 0.0.0.0`。

### 5. 启动

```bash
sshtun start            # 启动全部启用的隧道
sshtun start office     # 只启动指定隧道
sshtun start -d         # 后台运行
sshtun status           # 查看运行状态
sshtun list             # 列出隧道及路由/转发数量
sshtun stop             # 停止
```

> **TUN 模式需要特权**：Linux 用 root 运行，Windows 用管理员运行。
> 权限不足时 `sshtun check` 会明确提示。

---

## 命令行

```
sshtun start [tunnel|all]      启动隧道
sshtun stop [tunnel|all]       停止隧道
sshtun restart [tunnel|all]    重启隧道
sshtun status                  查看运行状态
sshtun list                    列出隧道及路由/转发数量
sshtun check [tunnel|all]      自检配置与运行环境
sshtun db tunnel|route|forward 管理隧道 / 路由 / 转发
sshtun web                     启动 Web 管理界面
sshtun version                 版本信息
```

多个隧道名用逗号分隔，或重复给出。`sshtun start -d` 在后台运行。

`sshtun check` 校验配置文件与数据库中的隧道，并自检运行环境（tun2socks 是否就绪、权限是否足够等）。
加 `--connect` 会额外测试每条隧道的 SSH 连接与认证。

### `sshtun db` 子命令

| 命令 | 说明 |
| --- | --- |
| `db tunnel list` / `show <name>` | 列出 / 查看隧道完整配置 |
| `db tunnel add [name]` | 新增隧道（省略参数进入交互向导） |
| `db tunnel set [name]` | 修改隧道（只覆盖显式给出的字段） |
| `db tunnel rm [name]` | 删除隧道（含其路由与转发） |
| `db tunnel enable/disable <name>` | 启用 / 停用 |
| `db route add <tunnel> <cidr[,cidr...]>` | 添加路由（`--bypass` 强制直连） |
| `db route list/rm <tunnel>` | 列出 / 删除路由 |
| `db forward add <tunnel> <local\|remote> <port[,port...]> <host:port[,...]>` | 添加端口转发 |
| `db forward list/rm <tunnel>` | 列出 / 删除转发 |

- `add` / `set` 在交互式终端下省略参数会进入**向导**，逐项询问并回填默认值
- `rm` 在交互式终端下会要求确认，`-y` 可跳过
- `db forward add` 支持 `--bind-addr`（监听地址）与 `--disable`（添加后先不启用）

---

## Web 界面

```bash
sshtun web                                    # 默认 127.0.0.1:8080
sshtun web --hostname 0.0.0.0 --port 9000
sshtun web --no-window                        # 只起服务，不自动开浏览器
sshtun web --username admin --password 'xxx' # 命令行覆盖配置
```

浏览器打开后即可管理隧道、查看流量与日志、修改设置。

- **界面语言**：设置 → 界面外观 → 界面语言（自动 / 简体中文 / English）。选「自动」时跟随浏览器系统语言
- **界面主题**：设置 → 界面外观 → 界面主题（自动 / 浅色 / 深色），顶栏按钮可快速切换
- **日志**：顶栏「运行日志」打开抽屉，可按隧道筛选；支持**自动刷新**（2 / 5 / 10 / 30 秒 / 1 分钟可选）并自动跳到最新一条

### 远程访问须知

`sshtun web` **只提供 HTTP，没有 TLS**。若要开放在网络上，务必：

1. 设置强密码（`--password` 或配置 `[web] password`）。绑定非回环地址时未设密码会被**拒绝启动**
2. **自行套一层 TLS**（反向代理 / 内网 / VPN），否则密码与会话 Cookie 会明文传输
3. 优先绑 `127.0.0.1`，用 SSH 隧道或 VPN 访问

---

## Windows 图形程序

`sshtun-gui.exe` 是内嵌 WebView2 的独立窗口：

- 双击运行；**关闭窗口（X）只是最小化到系统托盘**，托盘双击还原窗口，**托盘右键 → 退出** 才会真正退出并停止隧道、清理路由
- 提权时会显示 UAC「盾牌」提示
- 首次运行需要在系统安装 Microsoft Edge WebView2 运行时（Windows 10/11 通常已内置）
- 单实例：已有实例在运行时再次双击，会把原窗口唤到前台

---

## 配置文件

默认位置 `config/setting.conf`（相对当前工作目录），首次运行自动生成。
用 `-c/--config` 指定其他路径。

```ini
[app]
db = config/sshtun.db          ; 数据库路径（相对工作目录）

[web]
hostname = 127.0.0.1           ; 监听地址；0.0.0.0 表示对外开放
port = 8080                   ; 监听端口；0 表示由内核分配
cors =                        ; 允许的跨域源，逗号分隔；* 表示任意源
username = admin              ; 登录用户名
password =                    ; 登录密码（支持明文或 enc: 密文）
language =                    ; 可选：auto|zh|en；留空=跟随浏览器系统语言
theme =                       ; 可选：auto|light|dark；留空=跟随浏览器系统主题

[tun2socks]
path =                        ; tun2socks 路径；留空=自动查找

[ssh]
connect_timeout = 15          ; 连接超时（秒）
keepalive = 30                ; 保活间隔（秒）

[log]
level = info                  ; debug|info|warn|error
dir = log                     ; 日志目录；留空=只输出到控制台
console = auto                ; auto|true|false，是否同时输出到控制台
```

`language` 与 `theme` 是可选项（默认模板里没有这两行，留空即自动跟随）。
隧道、路由、转发存在数据库里，不在这个文件里。

---

## 依赖

| 组件 | 说明 |
| --- | --- |
| Go | ≥ 1.26（仅编译时需要） |
| tun2socks | 运行必需，版本随 `dl-tun2socks` 脚本获取 |
| wintun.dll | Windows 的 TUN 驱动，脚本会自动下载 |
| `/dev/net/tun` | Linux 需要，`modprobe tun` 加载 |
| WebView2 | 仅 `sshtun-gui` 需要 |

发布包提供 `linux-amd64` / `linux-arm64` / `windows-amd64` 三个平台。
其他平台（如 macOS）源码可编译，但未提供预编译包。

---

## 从源码构建

```bash
make build            # 构建本机版本
make build-linux      # 构建 linux-amd64 / linux-arm64
make build-windows    # 构建 windows-amd64（含 sshtun-gui.exe）
make all              # 全部平台
make dist             # 打包归档到 dist/（会自动递增版本号）
make t2s              # 预置各平台的 tun2socks 到包目录
make icon             # 重新生成 Windows 图标资源（.syso）
make test / vet       # 测试与静态检查
make clean            # 清理
```

产物都在项目内的 `dist/`。

`make dist` 生成的包只含二进制与对应平台的 `dl-tun2socks` 脚本 —— **不含 tun2socks / wintun / logo**，
由用户运行脚本自行获取最新版本。图标已内嵌进 exe（rsrc `.syso`）。

### 版本号

版本取自 `VERSION` 文件（其次 git tag）。`make dist` 会自动把补丁号 +1 并写回 `VERSION`；
`make dist VERSION=v1.2.3` 可指定而不递增。

### 密码加密种子

密码用 AES-256-GCM 加密，密钥由「编译期注入的种子 + 本机机器码」派生：

```bash
make dist SECRET=$(head -c 32 /dev/urandom | base64)
```

**每个部署应注入各自的随机种子**：种子内置在二进制里，机器码也可被读取，所以默认情况下
拿到数据库和二进制就等于拿到明文密码。注入独立种子后，即便两者同时泄露也无法解密。
注意：更换种子后，此前用旧种子加密的密码将无法解密，需要重新输入。

---

## 目录结构

```
.
├── main.go              程序入口
├── cmd/                 命令行与 Web 服务（cobra）
│   └── webui/           内嵌的前端资源（HTML/CSS/JS，双语）
├── gui/                 Windows 图形程序（WebView2 外壳）
├── internal/
│   ├── config/          配置解析与校验
│   ├── store/           SQLite 持久化（隧道/路由/转发）
│   ├── sshclient/       SSH 客户端（仅转发，不执行远端命令）
│   ├── tun2socks/       tun2socks 进程管理
│   ├── socks5/          SOCKS5 代理
│   ├── routing/         路由配置与清理（平台相关）
│   ├── forwarder/       端口转发
│   ├── hostkey/         主机密钥信任存储
│   ├── secret/          密码加密（机器码绑定）
│   ├── daemon/          后台化、状态文件、隧道锁
│   ├── logging/         日志
│   ├── traffic/         流量统计
│   ├── fetch/           tun2socks 下载
│   └── sshtest/         测试用 SSH 服务器
├── scripts/             dl-tun2socks.sh / .bat（随包分发）
├── tools/               构建辅助（fetch 下载 / mkpkg 打包）
├── assets/              logo.ico / logo.png / logo.svg / icon-*.png
└── config/              默认配置与数据库
```

---

## 安全须知

- **SSH 密码加密存储**，但默认种子是公开常量 —— 见上文「密码加密种子」，生产部署务必注入独立种子
- **隧道只做 TCP 转发**（`direct-tcpip` / `tcpip-forward`），**不会在对端执行任何命令**
- **Web 进程不持有明文凭据**：隧道运行在独立进程，解密只发生在隧道进程内
- **修改连接地址会使已存密码立即作废**，需重新输入 —— 避免「改了地址 → 密码被发到新地址」
- **Web 服务没有 TLS**：开放在网络上时务必自行套 TLS，并设置强密码
- **登录接口有限速**：同一来源 IP 连续失败会指数退避（30 秒起，上限 5 分钟）
- **绑定非回环地址时未设密码会被拒绝启动**；绑定回环地址时会校验 `Host` 头，阻断 DNS rebinding
- 同一时刻同一条隧道只能被一个实例占用（跨进程锁），避免 TUN 网卡被互删

---

## 许可

本仓库暂未附带 `LICENSE` 文件，使用或分发前请与作者确认授权条款。
