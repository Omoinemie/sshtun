// Package version 保存构建信息（ldflags 注入）。
package version

// RepoURL 是项目源码仓库地址，用于 `sshtun version` 等处展示。
const RepoURL = "https://github.com/Omoinemie/sshtun"

var (
	Version = "dev"
	Commit  = "none"
)
