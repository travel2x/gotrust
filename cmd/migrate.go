package cmd

import (
	"fmt"
	"net/url"
	"os"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/pop/v6/logging"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var migrateCmd = cobra.Command{
	Use:  "migrate",
	Long: "Migrate database strucutures. This will create new tables and add missing columns and indexes.",
	Run:  migrate,
}

func migrate(cmd *cobra.Command, args []string) {
	globalConfig := loadGlobalConfig(cmd.Context())
	if globalConfig.DB.Driver == "" && globalConfig.DB.URL != "" {
		u, err := url.Parse(globalConfig.DB.URL)
		if err != nil {
			logrus.Fatalf("%+v", errors.Wrap(err, "parsing db connection url"))
		}
		globalConfig.DB.Driver = u.Scheme
	}

	log := logrus.StandardLogger()
	pop.Debug = false

	if globalConfig.Logging.Level != "" {
		level, err := logrus.ParseLevel(globalConfig.Logging.Level)
		if err != nil {
			log.Fatalf("Failed to parse log level: %+v", err)
		}
		log.SetLevel(level)
		if level == logrus.DebugLevel {
			pop.Debug = true
		} else {
			var noopLogger = func(lvl logging.Level, s string, args ...interface{}) {}
			pop.SetLogger(noopLogger)
		}

	}

	u, _ := url.Parse(globalConfig.DB.URL)
	processedUrl := globalConfig.DB.URL

	if len(u.Query()) != 0 {
		processedUrl = fmt.Sprintf("%s&application_name=gotrust_migrations", processedUrl)
	} else {
		processedUrl = fmt.Sprintf("%s?application_name=gotrust_migrations", processedUrl)
	}

	connDetails := &pop.ConnectionDetails{
		Dialect: globalConfig.DB.Driver,
		URL:     processedUrl,
	}
	connDetails.Options = map[string]string{
		"migration_table_name": "schema_migrations",
		"Namespace":            globalConfig.DB.Namespace,
	}
	db, err := pop.NewConnection(connDetails)
	if err != nil {
		log.Fatalf("%+v", errors.Wrap(err, "opening db connection"))
	}
	defer db.Close()

	if err := db.Open(); err != nil {
		log.Fatalf("%+v", errors.Wrap(err, "checking database connection"))
	}
	log.Debugf("Reading migrations from %s", globalConfig.DB.MigrationsPath)

	migrations, err := pop.NewFileMigrator(globalConfig.DB.MigrationsPath, db)
	if err != nil {
		log.Fatalf("%+v", errors.Wrap(err, "creating db migrator"))
	}
	log.Debugf("before status")

	if log.Level == logrus.DebugLevel {
		err = migrations.Status(os.Stdout)
		if err != nil {
			log.Fatalf("%+v", errors.Wrap(err, "migration status"))
		}
	}

	migrations.SchemaPath = ""
	if err := migrations.Up(); err != nil {
		log.Fatalf("%v", errors.Wrap(err, "running db migrations"))
	} else {
		log.Infof("GoTrust migrations applied successfully")
	}

	log.Debugf("after status")
	if log.Level == logrus.DebugLevel {
		err = migrations.Status(os.Stdout)
		if err != nil {
			log.Fatalf("%+v", errors.Wrap(err, "migration status"))
		}
	}

}
