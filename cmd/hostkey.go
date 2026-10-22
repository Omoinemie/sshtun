package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/Omoinemie/sshtun/internal/hostkey"
	"github.com/Omoinemie/sshtun/internal/sshclient"
)

// isInteractive 报告当前进程是否可以与用户交互（非后台守护子进程）。
func isInteractive() bool {
	return os.Getenv(daemonEnv) != "1"
}

// interactiveHostKey 返回绑定到标准输入的确认提示器。
func interactiveHostKey() sshclient.HostKeyPrompter {
	return hostKeyPrompter(os.Stdin)
}

// hostKeyPrompter 返回从 r 读取确认输入的提示器。
// 输入不可读（非交互环境）时返回错误，避免进程挂起。
func hostKeyPrompter(r io.Reader) sshclient.HostKeyPrompter {
	in := bufio.NewReader(r)
	return func(address string, key ssh.PublicKey, status hostkey.Status) (bool, error) {
		if status == hostkey.StatusChanged {
			fmt.Printf("\nWarning: the host key of %s has changed!\n", address)
			fmt.Printf("  new key type %s, fingerprint %s\n", key.Type(), hostkey.Fingerprint(key))
			fmt.Println("  This may be a man-in-the-middle attack, or the server may simply have replaced its key.")
		} else {
			fmt.Printf("\nCannot confirm the identity of host %s.\n", address)
			fmt.Printf("  %s key fingerprint is %s\n", key.Type(), hostkey.Fingerprint(key))
		}
		fmt.Print("Continue connecting and store the key? [yes/no]: ")
		return readConfirm(in)
	}
}

// readConfirm 读取 yes/no 确认；EOF 或非法输入一律视为拒绝。
func readConfirm(in *bufio.Reader) (bool, error) {
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return false, fmt.Errorf("cannot read the confirmation (this is not an interactive session): %v", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "yes", "y":
		return true, nil
	default:
		return false, nil
	}
}
