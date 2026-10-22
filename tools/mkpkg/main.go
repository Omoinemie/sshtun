// Command mkpkg 打包 Linux 发行包（tar.gz）。
//
// 用于在 Windows 上打包：Windows 文件系统没有可执行位，bsdtar 会把二进制
// 记成 0666，解压到 Linux 后无法直接运行。本命令显式写入正确的 mode：
// 二进制 0755，脚本 0755，其余 0644。
//
// 用法:
//
//	go run ./tools/mkpkg -src dist/sshtun_v0.1.0_linux-amd64 -out dist/sshtun_v0.1.0_linux-amd64.tar.gz
package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	src := flag.String("src", "", "要打包的目录")
	out := flag.String("out", "", "输出的 tar.gz 路径")
	flag.Parse()

	if *src == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "用法: mkpkg -src <dir> -out <file.tar.gz>")
		os.Exit(1)
	}

	base := filepath.Base(*src)
	if err := pack(*src, base, *out); err != nil {
		fmt.Fprintf(os.Stderr, "打包失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("已生成:", *out)
}

// pack 将 src 目录打包为 out，其中目录名为 base。
func pack(src, base, out string) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		name := base
		if rel != "." {
			name = filepath.ToSlash(filepath.Join(base, rel))
		}

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = name
		hdr.Uid, hdr.Gid = 0, 0
		hdr.Uname, hdr.Gname = "root", "root"
		hdr.Mode = modeFor(info.Name())

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}

		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(tw, src)
		return err
	})
}

// modeFor 按文件名决定归档内的权限：可执行文件 0755，其余 0644。
func modeFor(name string) int64 {
	switch strings.ToLower(filepath.Ext(name)) {
	case "", ".sh":
		// 无扩展名的是 sshtun 二进制，.sh 是下载脚本，均需可执行。
		return 0755
	default:
		return 0644
	}
}
