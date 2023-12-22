#!/usr/bin/env bash

DB_ENV=$1

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DATABASE="$DIR/database.yml"

export GOTRUST_DB_DRIVER="postgres"
export GOTRUST_DB_DATABASE_URL="postgres://travel2x_auth_admin:root@localhost:5432/$DB_ENV"
export GOTRUST_DB_MIGRATIONS_PATH=$DIR/../migrations

go run main.go migrate -c $DIR/test.env
