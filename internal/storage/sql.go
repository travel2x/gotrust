package storage

func (conn *Connection) UpdateOnly(model interface{}, columns ...string) error {
	xcols, err := getExcludedColumns(model, columns...)
	if err != nil {
		return err
	}
	return conn.Update(model, xcols...)
}