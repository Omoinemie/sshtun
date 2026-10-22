package cmd

import (
	"github.com/Omoinemie/sshtun/internal/config"
)

// configLoad 统一的配置加载入口（读取全局 -c 标志）。
func configLoad() (*config.Config, error) {
	return config.Load(cfgFile)
}
