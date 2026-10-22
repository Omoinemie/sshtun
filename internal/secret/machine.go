package secret

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"sync"
)

// machineCode 是本机机器码：取值与其来源说明。
type machineCode struct {
	value  string
	source string
}

// machinePrint 返回参与密钥派生的机器码；测试可替换以模拟换机器。
var machinePrint = defaultMachinePrint

var (
	machineOnce sync.Once
	machineVal  string
	machineSrc  string
)

// loadMachineCode 依次取：硬件标识（主板/整机固件）→ 操作系统安装标识 → 主机名。
// 取到高优先级即停止，避免因主机名等易变项导致密文意外失效。
func loadMachineCode() machineCode {
	machineOnce.Do(func() {
		if v, s := platformHardwareID(); v != "" {
			machineVal, machineSrc = v, s
			return
		}
		if v, s := platformSoftwareID(); v != "" {
			machineVal, machineSrc = v, s
			return
		}
		host, _ := os.Hostname()
		if host = strings.TrimSpace(host); host != "" {
			machineVal, machineSrc = host, "hostname"
		} else {
			machineVal, machineSrc = "unknown-machine", "unknown source"
		}
	})
	return machineCode{value: machineVal, source: machineSrc}
}

// defaultMachinePrint 返回用于参与密钥派生的机器码取值。
func defaultMachinePrint() string { return loadMachineCode().value }

// MachineInfo 返回机器码摘要与来源（供 sshtun check 展示）。
// 摘要为 SHA-256 前 16 位十六进制，不回显原始机器码。
func MachineInfo() (digest, source string) {
	mc := loadMachineCode()
	sum := sha256.Sum256([]byte(mc.value))
	return hex.EncodeToString(sum[:])[:16], mc.source
}

// isMeaningfulID 判断标识是否可用：过滤空值、全相同字符、全零/全 F
// 的 UUID 以及固件常见的占位串（这类值在整批机器上相同，不能作为机器码）。
func isMeaningfulID(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	lower := strings.ToLower(s)
	for _, bad := range []string{
		"to be filled", "o.e.m", "not settable", "default string",
		"system serial number", "none", "unknown", "invalid",
	} {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	compact := strings.NewReplacer("-", "", ":", "", " ", "").Replace(lower)
	if len(compact) < 8 {
		return true
	}
	// 全相同字符（全 0、全 f、全 1 等）视为无效
	first := compact[0]
	same := true
	for i := 1; i < len(compact); i++ {
		if compact[i] != first {
			same = false
			break
		}
	}
	if same {
		return false
	}
	// 已知固件占位 UUID（AMI 默认值）
	if compact == "03000200040005000006000700080009" {
		return false
	}
	return true
}

// parseSMBIOSUUID 从 SMBIOS 原始表（GetSystemFirmwareTable("RSMB") 的返回值）
// 中提取系统信息（Type 1）的 UUID，按规范还原为标准 UUID 字符串。
// 该解析逻辑与平台无关，便于在任意平台测试。
func parseSMBIOSUUID(table []byte) string {
	if len(table) < 8 {
		return ""
	}
	structLen := int(binary.LittleEndian.Uint32(table[4:8]))
	end := len(table)
	if structLen > 0 && 8+structLen < end {
		end = 8 + structLen
	}
	for off := 8; off+4 <= end; {
		typ := table[off]
		l := int(table[off+1])
		if l < 4 {
			break
		}
		if typ == 1 && l >= 0x18 {
			return formatUUID(table[off+8 : off+24])
		}
		// 跳过格式化区与紧随其后的字符串区（以双 0 结束）
		next := off + l
		for next+1 < end && !(table[next] == 0 && table[next+1] == 0) {
			next++
		}
		if next+1 >= end {
			break
		}
		off = next + 2
	}
	return ""
}

// formatUUID 将 SMBIOS 的 16 字节 UUID 转为标准写法：
// 前三段按 SMBIOS 规范以小端存储，需还原字节序。
func formatUUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	rev := func(s []byte) string {
		return hex.EncodeToString([]byte{s[3], s[2], s[1], s[0]})
	}
	return rev(b[0:4]) + "-" + hex.EncodeToString([]byte{b[5], b[4]}) + "-" +
		hex.EncodeToString([]byte{b[7], b[6]}) + "-" + hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:16])
}
