// Command fetch 供打包脚本在单一主机上为各目标平台下载 tun2socks
// （目标为 Windows 时额外下载 wintun.dll）。由 Makefile 调用：
//
//	go run ./tools/fetch --os linux --arch amd64 -o dist/sshtun_v0.1.0_linux-amd64
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/Omoinemie/sshtun/internal/fetch"
	"github.com/Omoinemie/sshtun/internal/logging"
)

func main() {
	var (
		out      = flag.String("o", "bin", "输出目录")
		version  = flag.String("t2s-version", "", "tun2socks 版本（如 v2.5.3），默认最新")
		noWintun = flag.Bool("no-wintun", false, "跳过下载 wintun.dll（目标为 Windows 时）")
		goos     = flag.String("os", runtime.GOOS, "目标平台: linux|windows")
		goarch   = flag.String("arch", runtime.GOARCH, "目标架构: amd64|arm64")
	)
	flag.Parse()

	_ = logging.Setup("info", "", true)

	bin, err := fetch.Tun2socksFor(*out, *version, *goos, *goarch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "下载 tun2socks 失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("tun2socks:", bin)

	if *goos == "windows" && !*noWintun {
		dll, err := fetch.Wintun(*out, *goarch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "下载 wintun.dll 失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("wintun.dll:", dll)
	}
}
