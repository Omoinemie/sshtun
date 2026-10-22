BIN      := sshtun
# GUI_BIN 是 Windows 独立图形程序（内嵌 WebView2 的 web 界面）。
GUI_BIN  := sshtun-gui
# VERSION 优先取项目根目录的 VERSION 文件（非 git 环境同样可用）；其次 git tag，最后 dev。
# 需要临时覆盖时可用 `make VERSION=vX.Y.Z`。
# 以下必须用「递归赋值」（=）而非即时赋值（:=）：bump-version 会先改写 VERSION，
# 递归赋值才能在 recipe 执行时重新读取到递增后的版本号。
VERSION  ?= $(shell cat VERSION 2>/dev/null || git describe --tags --always 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
# SECRET 用于注入内置的密码加密种子（可选）。留空则使用程序内置默认值；
# 配置与二进制需配套：注入自定义 SECRET 后，此前用默认种子加密的密码将无法解密。
SECRET   ?=
CRYPTO   := $(if $(SECRET),-X github.com/Omoinemie/sshtun/internal/secret.embeddedSeed=$(SECRET),)
LDFLAGS  = -s -w -X github.com/Omoinemie/sshtun/internal/version.Version=$(VERSION) -X github.com/Omoinemie/sshtun/internal/version.Commit=$(COMMIT) $(CRYPTO)

# 所有产物都落在项目目录内的 dist/（不写入 /tmp 等外部路径）。
DIST     := dist
# T2S_VERSION 指定打包内置的 tun2socks 版本（留空取最新 release）。
T2S_VERSION ?=
T2S_ARGS := $(if $(T2S_VERSION),--t2s-version $(T2S_VERSION),)

.PHONY: build build-linux build-windows build-gui-windows all dist t2s icon test vet clean bump-version

# 本机平台
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN) .

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-linux-arm64 .

# 重新生成 Windows 图标资源（.syso）。产物已随仓库提交，正常构建无需执行；
# 仅当 assets/logo.ico 或 gui/sshtun-gui.manifest 变更时需要重跑（需可访问 Go module 代理）。
# 根目录 syso 供命令行 sshtun.exe 使用（仅图标，保持 asInvoker）；
# gui/ syso 额外内嵌 requireAdministrator 清单，使 sshtun-gui.exe 带「盾牌」并在启动时请求 UAC。
icon:
	go run github.com/akavel/rsrc@v0.10.2 -ico assets/logo.ico \
		-manifest gui/sshtun-gui.manifest -o gui/rsrc_windows_amd64.syso
	go run github.com/akavel/rsrc@v0.10.2 -ico assets/logo.ico -o rsrc_windows_amd64.syso
	@echo ">> 已生成 rsrc_windows_amd64.syso（CLI，仅图标）与 gui/rsrc_windows_amd64.syso（GUI，图标+管理员清单）"

# sshtun-gui：Windows 独立图形程序（仅 Windows 可用）。
# -H windowsgui 以 GUI 子系统构建，双击不弹控制台、也不触发 cobra 的 mousetrap 拦截。
build-gui-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS) -H windowsgui" -o $(DIST)/$(GUI_BIN)-windows-amd64.exe ./gui

build-windows: build-gui-windows
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-windows-amd64.exe .

# 全部平台
all: build-linux build-windows

# t2s：把各平台的 tun2socks 下载到对应包目录（Windows 额外含 wintun.dll）。
# 打包默认不再附带 tun2socks（由用户运行包内的 dl-tun2socks 脚本自行下载），
# 此目标保留给需要预置依赖的场景。
# GitHub 直连不通时可设 HTTPS_PROXY（Go 的 http 客户端会自动读取该环境变量）。
t2s:
	@set -e; \
	for p in linux-amd64 linux-arm64 windows-amd64; do \
		goos=$${p%%-*}; goarch=$${p##*-}; \
		d=$(DIST)/$(BIN)_$(VERSION)_$$p; \
		mkdir -p $$d; \
		echo ">> tun2socks $$goos/$$goarch -> $$d"; \
		go run ./tools/fetch --os $$goos --arch $$goarch -o $$d $(T2S_ARGS); \
	done

# bump-version：打包前自动递增补丁版本号（vX.Y.Z -> vX.Y.(Z+1)）并写回 VERSION 文件。
# 可用 make VERSION=vX.Y.Z 覆盖（命令行变量优先，不会触发递增）。
bump-version:
	@if [ "$(origin VERSION)" = "command line" ]; then \
		echo ">> 使用命令行指定的版本 $(VERSION)，跳过递增"; exit 0; \
	fi; \
	if [ "$(MAKELEVEL)" != "0" ]; then exit 0; fi; \
	v=$$(tr -d 'v \t\r\n' < VERSION 2>/dev/null); \
	v=$${v:-0.0.0}; \
	major=$${v%%.*}; rest=$${v#*.}; minor=$${rest%%.*}; patch=$${rest#*.}; \
	case "$$patch" in ''|*[!0-9]*) patch=0;; esac; \
	case "$$major" in ''|*[!0-9]*) major=0;; esac; \
	case "$$minor" in ''|*[!0-9]*) minor=0;; esac; \
	patch=$$((patch + 1)); \
	printf 'v%s.%s.%s\n' "$$major" "$$minor" "$$patch" > VERSION; \
	echo ">> 版本号已更新: v$$major.$$minor.$$patch"

# 打包：三平台二进制，归档到 dist/
# 每次打包自动递增补丁版本号（vX.Y.Z -> vX.Y.(Z+1)），保证产物版本号持续更新。
# 包内只含二进制与对应平台的 dl-tun2socks 脚本（Windows 用 .bat，Linux 用 .sh）；
# 图标已内嵌进 exe（rsrc .syso），无需随包分发 logo 文件；
# tun2socks 与 wintun.dll 也不随包分发，用户运行脚本自行下载最新版本。
dist: bump-version build-linux build-windows
	@set -e; \
	for p in linux-amd64 linux-arm64 windows-amd64; do \
		d=$(DIST)/$(BIN)_$(VERSION)_$$p; \
		rm -rf $$d; mkdir -p $$d; \
		exe=$(BIN); [ $$p = windows-amd64 ] && exe=$(BIN).exe; \
		cp $(DIST)/$(BIN)-$$p$$([ $$p = windows-amd64 ] && echo .exe) $$d/$$exe; \
		if [ $$p = windows-amd64 ]; then cp $(DIST)/$(GUI_BIN)-windows-amd64.exe $$d/$(GUI_BIN).exe; fi; \
		if [ $$p = windows-amd64 ]; then cp scripts/dl-tun2socks.bat $$d/; else cp scripts/dl-tun2socks.sh $$d/; fi; \
	done
	@set -e; \
	for p in linux-amd64 linux-arm64; do \
		go run ./tools/mkpkg -src $(DIST)/$(BIN)_$(VERSION)_$$p -out $(DIST)/$(BIN)_$(VERSION)_$$p.tar.gz; \
	done
	@set -e; \
	(cd $(DIST) && zip -qr $(BIN)_$(VERSION)_windows-amd64.zip $(BIN)_$(VERSION)_windows-amd64)
	@rm -f $(DIST)/$(BIN)-linux-amd64 $(DIST)/$(BIN)-linux-arm64 $(DIST)/$(BIN)-windows-amd64.exe $(DIST)/$(GUI_BIN)-windows-amd64.exe
	@ls -1 $(DIST)

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf $(DIST) $(BIN) $(BIN).exe $(GUI_BIN) $(GUI_BIN).exe
