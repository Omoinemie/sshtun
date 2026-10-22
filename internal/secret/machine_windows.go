//go:build windows

package secret

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32DLL                = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemFirmwareTable = kernel32DLL.NewProc("GetSystemFirmwareTable")
)

// platformHardwareID 返回与主板/整机固件绑定的机器码（重装系统后不变）。
// 取固件 SMBIOS 的系统信息(Type 1) UUID；取不到时由 platformSoftwareID 兜底。
func platformHardwareID() (string, string) {
	if u := smbiosSystemUUID(); isMeaningfulID(u) {
		return u, "SMBIOS system/board UUID"
	}
	return "", ""
}

// platformSoftwareID 返回 Windows 安装级标识（重装系统会变化）。
func platformSoftwareID() (string, string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", ""
	}
	if v = strings.TrimSpace(v); isMeaningfulID(v) {
		return v, "MachineGuid"
	}
	return "", ""
}

// smbiosSystemUUID 通过 GetSystemFirmwareTable('RSMB') 读取原始 SMBIOS 表，
// 取出系统 UUID。
func smbiosSystemUUID() string {
	const providerRSMB = 0x52534D42 // 'RSMB'
	size, _, _ := procGetSystemFirmwareTable.Call(providerRSMB, 0, 0, 0)
	if size == 0 {
		return ""
	}
	buf := make([]byte, size)
	n, _, _ := procGetSystemFirmwareTable.Call(providerRSMB, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(size))
	if n == 0 {
		return ""
	}
	if int(n) < len(buf) {
		buf = buf[:n]
	}
	return parseSMBIOSUUID(buf)
}
