package cmd

import (
	"github.com/spf13/cobra"
)

var configFile = ""
var rootCmd = cobra.Command{
	Use: "gotrust",
	Run: func(cmd *cobra.Command, args []string) {
		serve(cmd.Context())
	},
}

func RootCommand() *cobra.Command {
	rootCmd.AddCommand(
		&serveCmd,
	)
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "the config file to use")

	return &rootCmd
}
