//go:build !windows

// sshtun-gui 仅提供 Windows 图形界面；其它平台请使用 `sshtun web`。
// 此文件保证非 Windows 下 go build/vet ./... 仍能编译通过。
package main

import "fmt"

func main() {
	fmt.Println("sshtun-gui 仅支持 Windows；其它平台请使用 `sshtun web`。")
}
