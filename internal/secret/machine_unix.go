//go:build !windows

package secret

import (
	"os"
	"path/filepath"
	"strings"
)

// dmiRoot 是 Linux/Unix 的 DMI(SMBIOS) 信息目录，测试可替换为固定数据。
var dmiRoot = "/sys/class/dmi/id"

// platformHardwareID 返回与主板/整机固件绑定的机器码（换系统、重装后不变）。
// 依次尝试 SMBIOS 系统 UUID → 主板序列号 → 整机序列号；
// 这些文件通常仅 root 可读，读不到时由 platformSoftwareID 兜底。
func platformHardwareID() (string, string) {
	for _, c := range []struct {
		name   string
		source string
	}{
		{"product_uuid", "SMBIOS system/board UUID"},
		{"board_serial", "board serial number"},
		{"product_serial", "chassis serial number"},
	} {
		if v := readDMI(c.name); isMeaningfulID(v) {
			return v, c.source
		}
	}
	return "", ""
}

// platformSoftwareID 返回操作系统安装级标识（重装系统会变化）。
func platformSoftwareID() (string, string) {
	for _, c := range []struct {
		path   string
		source string
	}{
		{"/etc/machine-id", "machine-id (systemd)"},
		{"/var/lib/dbus/machine-id", "machine-id (dbus)"},
	} {
		b, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		if v := strings.TrimSpace(string(b)); isMeaningfulID(v) {
			return v, c.source
		}
	}
	return "", ""
}

func readDMI(name string) string {
	b, err := os.ReadFile(filepath.Join(dmiRoot, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
