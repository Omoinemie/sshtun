package cmd

import "fmt"

// fmtBytes 把字节数格式化为人类可读串（如 43.82 MB）。
func fmtBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// fmtRate 把字节/秒格式化为人类可读速率（如 9.47 MB/s）。
func fmtRate(bps float64) string {
	if bps < 1 {
		return "0 B/s"
	}
	return fmtBytes(int64(bps)) + "/s"
}
