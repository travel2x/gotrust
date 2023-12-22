package storage

import (
	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/pop/v6/columns"
	"github.com/travel2x/gotrust/internal/conf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/XSAM/otelsql"
	"github.com/jmoiron/sqlx"
	"reflect"
	"time"
	"context"
	"net/url"
)

type Connection struct {
	*pop.Connection
}

type CommitWithError struct {
	Err error
}

func (c *CommitWithError) Error() string {
	return c.Err.Error()
}

func (c *CommitWithError) Cause() error {
	return c.Err
}

func NewCommitWithError(err error) error {
	return &CommitWithError{Err: err}
}

func Dial(config *conf.GlobalConfiguration) (*Connection, error) {
	if config.DB.Driver == "" && config.DB.URL {
		u, err :=  url.Parse(config.DB.URL)
		if err != nil  {
			return nil, errors.Wrap(err, "Error parsing database URL")
		}
		config.DB.Driver = u.Scheme
	}

	driver := ""
	if config.DB.Driver != "postgres" {
		logrus.Warn("DEPRECATION NOTICE: only PostgreSQL is supported by GoTrust, will be removed soon")
	} else {
		driver = "pgx"
	}

	if driver != "" {
		instrumentedDriver, err := otelsql.Register(driver)
		if err != nil {
			logrus.WithError(err).Errorf("unable to instrument sql driver %q for use with OpenTelemetry", driver)
		} else {
			logrus.Debugf("using %s as an instrumented driver for OpenTelemetry", instrumentedDriver)
			sqlx.BindDriver(instrumentedDriver, sqlx.BindType(driver))
			driver = instrumentedDriver
		}
	}

	options := make(map[string]interface{})
	if config.DB.HealthCheckPeriod != time.Duration(0) {
		options["pool_health_check_period"] = config.DB.HealthCheckPeriod.String()
	}
	if config.DB.ConnMaxIdleTime != time.Duration(0) {
		options["pool_max_conn_idle_time"] = config.DB.ConnMaxIdleTime.String()
	}

	db, err := pop.NewConnection(&pop.ConnectionDetails{
		Dialect: 			config.DB.Driver,
		Driver:  			driver,
		URL:     			config.DB.URL,
		Pool:				config.DB.MaxPoolSize,
		IdlePool:			config.DB.MaxIdlePoolSize,
		ConnMaxLifetime:	config.DB.ConnMaxLifetime,
		Options:			options,
	})
	if err != nil {
		return nil, errors.Wrap(err, "opening database connection")
	}
	if err := db.Open(); err != nil {
		return nil, errors.Wrap(err, "checking database connection")
	}
	return &Connection{db}, nil
}

func (c *Connection) Transaction(fn func(*Connection) error) error {
	if c.TX != nil {
		var returnErr error
		if terr:= c.Connection.Transaction(func(tx *pop.Connection) error {
			err := fn(&Connection{tx})
			switch err.(type) {
			case *CommitWithError:
				returnErr = err
				return nil
			default:
				return err
			}
		}); terr != nil {
			return terr
		}
		return returnErr
	}
	return fn(c)
}

func (conn *Connection) WithContext(ctx context.Context) *Connection {
	return &Connection{conn.Connection.WithContext(ctx)}
}

// get all columns and remove included to get excluded set
func getExcludedColumns(model interface{}, includeColumns ...string) ([]string, error) {
	sm := pop.Model{Value: model}
	st := reflect.TypeOf(model)
	if st.Kind() == reflect.Ptr {
		_ = st.Elem()
	}

	cols := columns.ForStructWithAlias(model, sm.TableName(), sm.As, sm.IDField())
	for _, f := range includeColumns {
		if _, ok := cols.Cols[f]; !ok {
			return nil, errors.Errorf("Invalid column name %s", f)
		}
		cols.Remove(f)
	}

	xcols := make([]string, len(cols.Cols))
	for n := range cols.Cols {
		// gobuffalo updates the updated_at column automatically
		if n == "updated_at" {
			continue
		}
		xcols = append(xcols, n)
	}
	return xcols, nil
}