// Package cmd 定义 sshtun 的全部子命令。
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Omoinemie/sshtun/internal/config"
	"github.com/Omoinemie/sshtun/internal/store"
	"github.com/Omoinemie/sshtun/internal/version"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:           "sshtun",
	Short:         "Tunnel proxy tool built on tun2socks + SSH",
	SilenceUsage:  true,
	SilenceErrors: true,
	Version:       version.Version,
	// PersistentPreRunE 在任何子命令（以及无参数运行）之前确保本地基础状态就绪，
	// 使程序无需任何前置数据即可运行。
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		switch cmd.Name() {
		case "version", "help", "web":
			// web 自行在子命令内切换工作目录后加载配置，避免此处提前按默认目录读写。
			return nil
		}
		return ensureLocalState()
	},
	// RunE 使根命令可执行：无参数直接运行时打印帮助（在此之前 PersistentPreRunE
	// 已确保配置文件与数据库生成）。
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

// ensureLocalState 确保基础配置文件与数据库就绪：首次运行时自动生成
// ./config/setting.conf 与 ./config/sshtun.db。
func ensureLocalState() error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.App.DB)
	if err != nil {
		return err
	}
	return st.Close()
}

// Execute 运行根命令。
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", config.DefaultConfigPath(), "path to the config file (created automatically on first run)")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(restartCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(versionCmd)
}
