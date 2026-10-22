package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc, err := Encrypt("s3cr3t-pw")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if !IsEncrypted(enc) {
		t.Fatalf("应以 %s 开头: %s", prefix, enc)
	}
	if strings.Contains(enc, "s3cr3t-pw") {
		t.Fatal("密文中不应出现明文")
	}
	got, err := Decrypt(enc)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if got != "s3cr3t-pw" {
		t.Fatalf("解密结果错误: %q", got)
	}
}

func TestIsEncrypted(t *testing.T) {
	if IsEncrypted("plaintext") {
		t.Fatal("明文不应被判定为加密格式")
	}
	if IsEncrypted("enc:v1:AAAA") {
		t.Fatal("旧版 enc:v1 格式不应再被识别")
	}
	if !IsEncrypted(prefix + "AAAA") {
		t.Fatal("加密前缀应被识别")
	}
}

func TestDecryptRejectsPlaintext(t *testing.T) {
	if _, err := Decrypt("plaintext"); err == nil {
		t.Fatal("非加密格式应报错")
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	enc, err := Encrypt("x")
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimPrefix(enc, prefix)
	// 改动中部的字符：末尾 base64 填充位可能不含有效位，改动后解码结果可能不变。
	i := len(body) / 2
	c := "A"
	if body[i:i+1] == "A" {
		c = "B"
	}
	tampered := prefix + body[:i] + c + body[i+1:]
	if _, err := Decrypt(tampered); err == nil {
		t.Fatal("篡改后的密文应解密失败")
	}
}

// 更换内置种子（等价于换了一版二进制）后，旧密文不可解密。
func TestDecryptFailsWithDifferentEmbeddedSeed(t *testing.T) {
	old := embeddedSeed
	defer func() { embeddedSeed = old }()

	enc, err := Encrypt("x")
	if err != nil {
		t.Fatal(err)
	}
	embeddedSeed = old + "-other"
	if _, err := Decrypt(enc); err == nil {
		t.Fatal("内置种子不同时应解密失败")
	}
}

// 密文与机器码绑定：换机器（机器码变化）后无法解密，回到原机器仍可解密。
func TestDecryptFailsOnDifferentMachine(t *testing.T) {
	orig := machinePrint
	defer func() { machinePrint = orig }()

	machinePrint = func() string { return "machine-a" }
	enc, err := Encrypt("x")
	if err != nil {
		t.Fatal(err)
	}

	machinePrint = func() string { return "machine-b" }
	if _, err := Decrypt(enc); err == nil {
		t.Fatal("换机器后应解密失败")
	}

	machinePrint = func() string { return "machine-a" }
	if got, err := Decrypt(enc); err != nil || got != "x" {
		t.Fatalf("回到原机器应可解密: %q, %v", got, err)
	}
}

// 机器码应可正常取到，且来源可识别。
func TestMachineCode(t *testing.T) {
	digest, source := MachineInfo()
	if len(digest) != 16 {
		t.Fatalf("机器码摘要应为 16 位十六进制，实际 %q", digest)
	}
	if strings.Contains(digest, "-") || strings.Contains(digest, " ") {
		t.Fatalf("机器码摘要格式异常: %q", digest)
	}
	if source == "" {
		t.Fatal("机器码来源不应为空")
	}
	if defaultMachinePrint() == "" {
		t.Fatal("参与密钥派生的机器码不应为空")
	}
}

// 运行期不得产生任何本地密钥文件。
func TestNoLocalKeyFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, err := Encrypt("x"); err != nil {
		t.Fatal(err)
	}
	enc, err := Encrypt("y")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(enc); err != nil {
		t.Fatal(err)
	}

	var found []string
	_ = filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			found = append(found, path)
		}
		return nil
	})
	if len(found) != 0 {
		t.Fatalf("不应创建任何本地文件，实际: %v", found)
	}
}
