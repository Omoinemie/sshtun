//go:build !windows

package secret

import (
	"os"
	"path/filepath"
	"testing"
)

// Linux 硬件机器码：优先 SMBIOS 系统 UUID，无效时退到主板序列号。
func TestPlatformHardwareIDFromDMI(t *testing.T) {
	dir := t.TempDir()
	orig := dmiRoot
	dmiRoot = dir
	defer func() { dmiRoot = orig }()

	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("product_uuid", " 7012d3a4-1b2c-4d5e-8f90-a1b2c3d4e5f6 \n")
	if v, src := platformHardwareID(); v != "7012d3a4-1b2c-4d5e-8f90-a1b2c3d4e5f6" || src != "SMBIOS 系统/主板 UUID" {
		t.Fatalf("应取系统 UUID: got %q (%s)", v, src)
	}

	// 固件占位 UUID 应被跳过，改用主板序列号
	write("product_uuid", "00000000-0000-0000-0000-000000000000")
	write("board_serial", "MB-1234567890")
	if v, src := platformHardwareID(); v != "MB-1234567890" || src != "主板序列号" {
		t.Fatalf("应退回主板序列号: got %q (%s)", v, src)
	}

	// 都拿不到时返回空，交由 software/主机名兜底
	write("board_serial", "Default string")
	if v, _ := platformHardwareID(); v != "" {
		t.Fatalf("无有效硬件标识时应返回空，实际 %q", v)
	}
}
