package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/Omoinemie/sshtun/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("sshtun %s (%s) %s/%s\n", version.Version, version.Commit, runtime.GOOS, runtime.GOARCH)
		fmt.Printf("source: %s\n", version.RepoURL)
	},
}
