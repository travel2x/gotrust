package cmd

import (
	"context"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/travel2x/gotrust/internal/conf"
)

var configFile = ""
var rootCmd = cobra.Command{
	Use: "gotrust",
	Run: func(cmd *cobra.Command, args []string) {
		migrate(cmd, args)
		serve(cmd.Context())
	},
}

func RootCommand() *cobra.Command {
	rootCmd.AddCommand(
		&migrateCmd,
		&serveCmd,
	)
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "the config file to use")

	return &rootCmd
}

func loadGlobalConfig(ctx context.Context) *conf.GlobalConfiguration {
	if ctx == nil {
		panic("context must not be nil")
	}
	config, err := conf.LoadGlobal(configFile)
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %+v", err)
	}
	return config
}

func execWithConfigAndArgs(cmd *cobra.Command, fn func(config *conf.GlobalConfiguration, args []string), args []string) {
	fn(loadGlobalConfig(cmd.Context()), args)
}
