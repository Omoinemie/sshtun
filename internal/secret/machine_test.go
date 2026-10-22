package secret

import (
	"encoding/binary"
	"testing"
)

func TestIsMeaningfulID(t *testing.T) {
	bad := []string{
		"",
		"   ",
		"00000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
		"11111111-1111-1111-1111-111111111111",
		"03000200-0400-0500-0006-000700080009", // AMI 固件占位 UUID
		"To be filled by O.E.M.",
		"Default string",
		"Not Settable",
	}
	for _, s := range bad {
		if isMeaningfulID(s) {
			t.Errorf("%q 应判为无效标识", s)
		}
	}
	good := []string{
		"b6e64419ee494d5b98b56c58e9733cf0",
		"7012d3a4-1b2c-4d5e-8f90-a1b2c3d4e5f6",
		"MB-1234567890",
	}
	for _, s := range good {
		if !isMeaningfulID(s) {
			t.Errorf("%q 应判为有效标识", s)
		}
	}
}

func TestFormatUUID(t *testing.T) {
	b := []byte{0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}
	if got, want := formatUUID(b), "11223344-5566-7788-99aa-bbccddeeff00"; got != want {
		t.Fatalf("formatUUID 错误: got %s want %s", got, want)
	}
	if formatUUID([]byte{1, 2, 3}) != "" {
		t.Fatal("长度不是 16 时应返回空")
	}
}

// 构造 SMBIOS 原始表：先一块 Type 2(含字符串)，再到 Type 1(含 UUID)。
func smbiosTable(withSystem bool) []byte {
	uuid := []byte{0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}

	// Type 2：长度 0x0f + 1 个字符串 + 结束符
	type2 := make([]byte, 0x0f)
	type2[0], type2[1] = 2, 0x0f
	type2 = append(type2, []byte("BB\x00")...)
	type2 = append(type2, 0)

	var structures []byte
	structures = append(structures, type2...)
	if withSystem {
		type1 := make([]byte, 0x18)
		type1[0], type1[1] = 1, 0x18
		type1[4], type1[5], type1[6], type1[7] = 1, 2, 3, 4
		copy(type1[8:24], uuid)
		structures = append(structures, type1...)
		structures = append(structures, []byte("Mfr\x00Prod\x00Ver\x00Ser\x00\x00")...)
	}

	table := make([]byte, 8)
	table[1], table[2], table[3] = 3, 6, 0 // SMBIOS 3.6
	binary.LittleEndian.PutUint32(table[4:8], uint32(len(structures)))
	return append(table, structures...)
}

func TestParseSMBIOSUUID(t *testing.T) {
	got := parseSMBIOSUUID(smbiosTable(true))
	if want := "11223344-5566-7788-99aa-bbccddeeff00"; got != want {
		t.Fatalf("解析结果错误: got %q want %q", got, want)
	}
}

// 表中没有 Type 1 时不应误取其他结构的数据。
func TestParseSMBIOSUUIDNoSystemInfo(t *testing.T) {
	if got := parseSMBIOSUUID(smbiosTable(false)); got != "" {
		t.Fatalf("无 Type 1 结构时应返回空，实际 %q", got)
	}
	if got := parseSMBIOSUUID([]byte{1, 2, 3}); got != "" {
		t.Fatalf("表过短时应返回空，实际 %q", got)
	}
}
