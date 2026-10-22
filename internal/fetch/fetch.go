// Package fetch 从 GitHub Releases 下载 tun2socks（Windows 额外下载 wintun.dll）。
package fetch

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Omoinemie/sshtun/internal/logging"
)

const (
	t2sRepo   = "xjasonlyu/tun2socks"
	wintunURL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
)

// Tun2socksFor 下载指定平台(goos/goarch)的 tun2socks 到 outputDir，返回二进制路径。
// 供打包时在单一平台上收集各平台资产（如 Linux 上准备 Windows 版）。
func Tun2socksFor(outputDir, version, goos, goarch string) (string, error) {
	tag, assetURL, err := resolveAsset(goos, goarch, version)
	if err != nil {
		return "", err
	}
	logging.Info("downloading tun2socks", "tag", tag, "url", assetURL)
	data, err := download(assetURL)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	// 目标平台为 Windows 时，解压出的文件名必须是 tun2socks.exe
	// （zips 内的文件名随发布平台而定，不能依赖 runtime.GOOS 判断）。
	name := "tun2socks"
	if goos == "windows" {
		name = "tun2socks.exe"
	}
	binPath := filepath.Join(outputDir, name)

	if strings.HasSuffix(assetURL, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return "", fmt.Errorf("failed to extract the zip archive: %w", err)
		}
		var found bool
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			base := strings.ToLower(filepath.Base(f.Name))
			if strings.HasPrefix(base, "tun2socks") && !strings.HasSuffix(base, ".txt") {
				rc, err := f.Open()
				if err != nil {
					return "", err
				}
				err = writeFile(binPath, rc, 0o755)
				rc.Close()
				if err != nil {
					return "", err
				}
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("tun2socks executable not found in the zip archive")
		}
	} else {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return "", fmt.Errorf("failed to extract the gz archive: %w", err)
		}
		if err := writeFile(binPath, gz, 0o755); err != nil {
			gz.Close()
			return "", err
		}
		gz.Close()
	}
	logging.Info("tun2socks is ready", "path", binPath, "version", tag)
	return binPath, nil
}

// resolveAsset 解析指定平台的资产下载地址。
func resolveAsset(goos, goarch, version string) (tag, assetURL string, err error) {
	want := fmt.Sprintf("tun2socks-%s-%s", goos, goarch)
	exts := []string{".gz", ".zip"}
	if goos == "windows" {
		exts = []string{".zip", ".gz"}
	}

	if version == "" {
		if t, err := latestTagByRedirect(); err == nil {
			version = t
		} else {
			return "", "", fmt.Errorf("failed to get the latest version: %w", err)
		}
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", t2sRepo, version, want)
	for _, ext := range exts {
		if ok, _ := reachable(base + ext); ok {
			return version, base + ext, nil
		}
	}
	return "", "", fmt.Errorf("release %s: no asset found for platform %s", version, want)
}

// latestTagByRedirect 通过 releases/latest 页面重定向获取最新 tag（绕开 API 限流）。
func latestTagByRedirect() (string, error) {
	url := fmt.Sprintf("https://github.com/%s/releases/latest", t2sRepo)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "sshtun")
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随重定向
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	// 形如 https://github.com/xjasonlyu/tun2socks/releases/tag/v2.5.3
	i := strings.LastIndex(loc, "/tag/")
	if i < 0 {
		return "", fmt.Errorf("cannot parse the version from the redirect: %q", loc)
	}
	return strings.TrimSpace(loc[i+len("/tag/"):]), nil
}

// reachable 探测 URL 是否可下载（优先 HEAD，避免为一个探测请求拉取整份二进制）。
func reachable(url string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "sshtun")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	// 部分下载源不支持 HEAD：退回 GET，但仍只读少量数据后立即关闭。
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
		return reachableByGet(url)
	}
	return false, nil
}

func reachableByGet(url string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "sshtun")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1))
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// Wintun 下载 wintun.dll（仅 Windows 需要），放到 outputDir。
// goarch 为空时取当前架构。
func Wintun(outputDir, goarch string) (string, error) {
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	logging.Info("downloading wintun.dll", "url", wintunURL)
	data, err := download(wintunURL)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("failed to extract the wintun archive: %w", err)
	}
	// 目标架构优先，其次 amd64/arm64 兜底
	candidates := []string{
		"wintun/bin/" + goarch + "/wintun.dll",
		"wintun/bin/amd64/wintun.dll",
		"wintun/bin/arm64/wintun.dll",
	}
	for _, want := range candidates {
		for _, f := range zr.File {
			if strings.EqualFold(strings.ReplaceAll(f.Name, "\\", "/"), want) {
				dst := filepath.Join(outputDir, "wintun.dll")
				rc, err := f.Open()
				if err != nil {
					return "", err
				}
				err = writeFile(dst, rc, 0o644)
				rc.Close()
				if err != nil {
					return "", err
				}
				logging.Info("wintun.dll is ready", "path", dst)
				return dst, nil
			}
		}
	}
	return "", fmt.Errorf("no amd64/arm64 wintun.dll found in the wintun archive")
}

func download(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sshtun")
	// 默认 Transport 自动遵循 HTTP(S)_PROXY 环境变量
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		return nil, fmt.Errorf("failed to download %s: HTTP %d %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(resp.Body)
}

func writeFile(dst string, r io.Reader, mode os.FileMode) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, r)
	return err
}
