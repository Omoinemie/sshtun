package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/logging"
	"github.com/Omoinemie/sshtun/internal/secret"
	"github.com/Omoinemie/sshtun/internal/sshclient"
)

// maxAuthAttempts 限制认证失败后的重试次数，避免无限循环。
const maxAuthAttempts = 3

// authPrompts 是认证重试时可用的交互输入；字段为 nil 表示该项不可提示。
// （SSH 的失败反馈不区分「用户名不存在」与「密码/密钥错误」，故两者都可更正。）
type authPrompts struct {
	// user 提示用户名，current 为当前值；返回空串表示保持不变。
	user func(current string) (string, error)
	// pass 提示密码（不回显）。
	pass func() (string, error)
}

// CredentialSaver 持久化认证重试时更新的用户名/加密密码。
// 多隧道场景下每条隧道对应一个 saver（写回数据库）。
type CredentialSaver interface {
	SaveUser(user string) error
	SavePassword(encPassword string) error
}

// interactivePrompts 返回绑定终端的提示器；不可交互时两者均为 nil。
func interactivePrompts() authPrompts {
	if !isInteractive() {
		return authPrompts{}
	}
	return authPrompts{user: interactiveUser, pass: interactivePassword}
}

// connectWithPassword 完成登录：以 SSH 的实际反馈为准决定是否提示凭据。
//  1. 先解析密码（必要时提示输入并加密保存到 saver），再尝试连接；
//  2. 若对端拒绝认证，说明用户名或密码不被接受：在可交互时提示用户名
//     （回车保持不变）与密码，保存后重试；
//  3. 若为网络层失败（拨号不通/超时/主机密钥未受信任），直接返回错误，不提示凭据。
//
// 后台守护子进程不可交互，认证失败会直接报错，提示用户前台重跑以更新凭据。
func connectWithPassword(cfg *config.Config, cli *sshclient.Client, saver CredentialSaver) error {
	return connectWithPrompts(cfg, cli, interactivePrompts(), saver)
}

// connectWithPrompts 是 connectWithPassword 的可注入形式。
func connectWithPrompts(cfg *config.Config, cli *sshclient.Client, p authPrompts, saver CredentialSaver) error {
	if cfg.SSH.Auth == "password" {
		changed, err := resolvePassword(cfg, p.pass)
		if err != nil {
			return err
		}
		if changed {
			if serr := persistPassword(saver, cfg.SSH.Password); serr != nil {
				return serr
			}
		}
	}
	err := cli.Connect()
	if err == nil || !sshclient.IsAuthError(err) {
		return err
	}

	if p.user == nil && p.pass == nil {
		return fmt.Errorf("%w\nhint: the background mode cannot prompt, run `sshtun start -c <config>` in the foreground to check the user/password of this tunnel", err)
	}
	for attempt := 1; attempt <= maxAuthAttempts; attempt++ {
		logging.Warn("the SSH server rejected the authentication (the user name or the credentials are not accepted)", "attempt", attempt, "user", cfg.SSH.User, "endpoint", cfg.SSHEndpoint())
		fmt.Printf("Authentication failed: %s rejected the current user name or credentials (they may have changed on the server).\n", cfg.SSHEndpoint())
		if p.user != nil {
			user, uerr := p.user(cfg.SSH.User)
			if uerr != nil {
				return uerr
			}
			if user != "" && user != cfg.SSH.User {
				if serr := persistUser(saver, cfg, user); serr != nil {
					return serr
				}
			}
		}
		if cfg.SSH.Auth == "password" && p.pass != nil {
			pwd, perr := p.pass()
			if perr != nil {
				return perr
			}
			if serr := persistPassword(saver, pwd); serr != nil {
				return serr
			}
			cfg.SSH.Password = pwd
		}
		if err = cli.Connect(); err == nil {
			return nil
		}
		if !sshclient.IsAuthError(err) {
			return err
		}
	}
	return fmt.Errorf("%w\nhint: %d consecutive authentication failures, check the user and the password (or key_file) of this tunnel before retrying", err, maxAuthAttempts)
}

// persistUser 更新内存中的用户名并持久化到 saver。
func persistUser(saver CredentialSaver, cfg *config.Config, user string) error {
	cfg.SSH.User = user
	if saver == nil {
		return nil
	}
	if err := saver.SaveUser(user); err != nil {
		logging.Warn("failed to save the user name (this connection is not affected)", "err", err)
		return nil
	}
	fmt.Println("The user name has been updated and saved")
	return nil
}

// interactiveUser 从终端读取用户名；直接回车表示保持当前值。
func interactiveUser(current string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("this is not an interactive terminal, the user name cannot be entered")
	}
	fmt.Printf("SSH user name [press Enter to keep %s]: ", current)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		fmt.Println()
		return "", fmt.Errorf("failed to read the user name: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// resolvePassword 解析登录密码，返回是否为新输入（需要持久化）：
//   - 配置值为加密格式且可解密时，直接使用（changed=false）；
//   - 其余情况（明文、空值、解密失败）忽略配置值，由 prompt 交互输入，
//     返回 changed=true，调用方加密后写入 saver。
//
// prompt 为空表示当前不可交互，此时直接报错。
func resolvePassword(cfg *config.Config, prompt func() (string, error)) (bool, error) {
	raw := cfg.SSH.Password
	if secret.IsEncrypted(raw) {
		if pwd, err := secret.Decrypt(raw); err == nil {
			cfg.SSH.Password = pwd
			return false, nil
		}
		logging.Warn("the encrypted password cannot be decrypted (the ciphertext is bound to this machine's machine code, so it breaks on another machine or after a hostname change), it will be entered again")
	} else if strings.TrimSpace(raw) != "" {
		logging.Warn("the password is stored in plain text, it is ignored; it will be entered again and stored encrypted")
	}

	if prompt == nil {
		return false, fmt.Errorf("auth=password needs an encrypted password, and the current session is not interactive; run it in the foreground to enter the password")
	}
	pwd, err := prompt()
	if err != nil {
		return false, err
	}
	cfg.SSH.Password = pwd
	return true, nil
}

// persistPassword 将密码加密后写入 saver；saver 为空时仅停留在内存。
func persistPassword(saver CredentialSaver, pwd string) error {
	if pwd == "" {
		return fmt.Errorf("the password is empty, cancelled")
	}
	if saver == nil {
		return nil
	}
	enc, err := secret.Encrypt(pwd)
	if err != nil {
		return fmt.Errorf("failed to encrypt the password: %w", err)
	}
	if err := saver.SavePassword(enc); err != nil {
		logging.Warn("failed to save the encrypted password (this connection is not affected)", "err", err)
		return nil
	}
	fmt.Println("The password has been encrypted and saved to the database")
	return nil
}

// interactivePassword 从终端读取密码，输入不回显。
func interactivePassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("this is not an interactive terminal, the password cannot be entered safely")
	}
	fmt.Print("SSH login password (not echoed): ")
	b, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("failed to read the password: %w", err)
	}
	pwd := strings.TrimSpace(string(b))
	if pwd == "" {
		return "", fmt.Errorf("the password is empty, cancelled")
	}
	return pwd, nil
}
