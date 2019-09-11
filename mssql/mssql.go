package mssql

import (
	"context"
	"database/sql"
	"net"

	"cloud.google.com/go/cloudsql/dialer"
	mssql "github.com/denisenkom/go-mssqldb"
	"google.golang.org/api/option"
)

// TODO(cbro): read instance name from dsn?

func Open(ctx context.Context, instance, dsn string, opts ...option.ClientOption) (*sql.DB, error) {
	client, err := dialer.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	connector, err := mssql.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	connector.Dialer = netDialer{client, instance}

	db := sql.OpenDB(connector)
	return db, db.Ping()
}

type netDialer struct {
	dc   *dialer.Client
	inst string
}

func (d netDialer) DialContext(ctx context.Context, net, addr string) (net.Conn, error) {
	return d.dc.DialContext(ctx, d.inst)
}
