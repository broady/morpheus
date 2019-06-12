package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net"
	"time"

	"cloud.google.com/go/cloudsql/dialer"
	"github.com/lib/pq"
	"google.golang.org/api/option"
)

func Open(ctx context.Context, instance string, opts ...option.ClientOption) (*sql.DB, error) {
	client, err := dialer.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	db := sql.OpenDB(&connector{dialClient: client, instance: instance})
	return db, db.Ping()
}

type connector struct {
	dialClient *dialer.Client
	instance   string
}

// type check
var _ driver.Connector = &connector{}
var _ pq.Dialer = &connector{}
var _ pq.DialerContext = &connector{}

func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	return pq.DialOpen(c, "sslmode=disable") // TODO(cbro): expose some pq options (user, password, etc at minimum)
}

func (c *connector) Driver() driver.Driver {
	return &pq.Driver{}
}

func (c *connector) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return c.dialClient.DialContext(ctx, c.instance)
}

func (c *connector) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

func (c *connector) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return c.DialContext(ctx, network, address)
}
