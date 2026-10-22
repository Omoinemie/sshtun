// Package secret 负责 SSH 登录密码的本地加密存储。
// 采用 AES-256-GCM，密钥由「编译期内置种子 + 本机机器码」经 HKDF-SHA256 派生，
// 运行期不产生、不依赖任何本地密钥文件；密文以 enc:v3:<base64> 形式写入配置文件。
//
// 因此密文与本机绑定：换机器（或改主机名）后无法解密，会重新提示输入密码。
// 注意：种子内置于二进制、机器码也可读取，故该方案属于「避免明文落盘 + 换机失效」
// 的混淆级保护，而非强加密。若需更强隔离，可在构建时用 -X 注入每个部署独有的随机种子
// （见 Makefile 的 SECRET）。
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	prefix  = "enc:v3:"
	keySize = 32
	keyInfo = "sshtun password storage key v3"
)

// embeddedSeed 是编译期注入的密钥种子。
// 构建时可覆盖：-ldflags "-X github.com/Omoinemie/sshtun/internal/secret.embeddedSeed=<随机串>"。
var embeddedSeed = "sshtun-builtin-seed-v3"

// IsEncrypted 报告 s 是否为加密存储格式。
func IsEncrypted(s string) bool {
	return strings.HasPrefix(s, prefix)
}

// Encrypt 加密明文，返回 enc:v3:<base64> 形式。
func Encrypt(plain string) (string, error) {
	gcm, err := newGCM()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate the random nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return prefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Decrypt 解密 enc:v3:<base64> 形式的密文，返回明文。
// 若密文来自其他机器（机器码不同），会返回解密失败。
func Decrypt(s string) (string, error) {
	if !IsEncrypted(s) {
		return "", fmt.Errorf("not in the encrypted storage format")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext encoding: %w", err)
	}
	gcm, err := newGCM()
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", fmt.Errorf("invalid ciphertext length")
	}
	plain, err := gcm.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (not this machine's machine code, the seed does not match, or the data is corrupted): %w", err)
	}
	return string(plain), nil
}

func newGCM() (cipher.AEAD, error) {
	block, err := aes.NewCipher(deriveKey())
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// deriveKey 由内置种子与本机机器码派生 32 字节 AES 密钥。
// 机器码参与 salt，使密文仅在当前机器可解密。
func deriveKey() []byte {
	key := make([]byte, keySize)
	// HKDF 不会失败（参数与长度均有效）
	_, _ = io.ReadFull(hkdf.New(sha256.New, []byte(embeddedSeed), []byte(machinePrint()), []byte(keyInfo)), key)
	return key
}
