package cmd

import (
	"context"
	"github.com/travel2x/gotrust/internal/api"
	"github.com/travel2x/gotrust/internal/storage"
	"github.com/travel2x/gotrust/internal/utilities"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/travel2x/gotrust/internal/conf"
)

var serveCmd = cobra.Command{
	Use:  "serve",
	Long: "Start API server",
	Run: func(cmd *cobra.Command, args []string) {
		serve(cmd.Context())
	},
}

func serve(ctx context.Context) {
	config, err := conf.LoadGlobal(configFile)
	if err != nil {
		logrus.WithError(err).Fatal("unable to load config")
	}

	db, err := storage.Dial(config)
	if err != nil {
		logrus.WithError(err).Fatal("unable to load config")
	}

	addr := net.JoinHostPort(config.API.Host, config.API.Port)
	serv := api.NewAPIWithVersion(ctx, config, db, utilities.Version)
	logrus.Info("GoTrust API started on: %s", addr)

	serv.ListenAndServe(ctx, addr)
}
