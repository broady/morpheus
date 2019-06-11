// Copyright 2019 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dialer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

var defaultDialer = &net.Dialer{
	KeepAlive: time.Minute,
}

type Client struct {
	api *sqladmin.Service

	privateKey   *rsa.PrivateKey
	publicKeyPem string

	mu        sync.Mutex
	instances map[string]*dbInstance
}

func NewClient(ctx context.Context, opts ...option.ClientOption) (*Client, error) {
	c := &Client{instances: make(map[string]*dbInstance)}
	var err error

	// TODO(cbro): add default options for user-agent.
	c.api, err = sqladmin.NewService(ctx, opts...)
	if err != nil {
		return nil, err
	}

	c.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pkix, err := x509.MarshalPKIXPublicKey(c.privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("MarshalPKIXPublicKey: %v", err)
	}
	c.publicKeyPem = string(pem.EncodeToMemory(&pem.Block{Bytes: pkix, Type: "RSA PUBLIC KEY"}))

	return c, nil
}

func (c *Client) DialContext(ctx context.Context, instance string) (net.Conn, error) {
	inst, err := c.getInstance(instance)
	if err != nil {
		return nil, err
	}

	return inst.dial(ctx)
}

func (c *Client) getInstance(instance string) (*dbInstance, error) {
	parts := strings.Split(instance, ":")
	if len(parts) != 3 {
		// TODO(cbro): handle "google.com:foo" project IDs.
		return nil, errors.New("format of instance name is 'project:zone:name'")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	inst, ok := c.instances[instance]
	if ok {
		return inst, nil
	}

	inst = &dbInstance{
		client:  c,
		project: parts[0],
		zone:    parts[1],
		name:    parts[2],
	}
	c.instances[instance] = inst
	return inst, nil
}

type dbInstance struct {
	client              *Client
	project, zone, name string

	mu sync.Mutex

	conns []*connWrapper

	checked time.Time // time this config was retrieved.

	expires   time.Time // time until the cert/instance config is expired.
	tlsConfig *tls.Config
	dbConfig  *sqladmin.DatabaseInstance

	// Everything above is guarded by mu.
}

func (i *dbInstance) dial(ctx context.Context) (net.Conn, error) {
	addr, tlsConfig, err := i.dialConfig(ctx, false)
	if err != nil {
		return nil, err
	}

	conn, err := i.tryDial(ctx, addr, tlsConfig)
	if err == nil {
		// success
		return conn, nil
	}

	// Try again, refreshing the cert this time.
	addr, tlsConfig, err = i.dialConfig(ctx, true)
	if err != nil {
		// TODO(cbro): combine with err from tryDial? probably not.
		return nil, err
	}

	return i.tryDial(ctx, addr, tlsConfig)
}

func (i *dbInstance) dialConfig(ctx context.Context, forceFetch bool) (addr string, cfg *tls.Config, err error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	// TODO(cbro): cache failures in fetchConfig.
	// TODO(cbro): check SECOND_GEN etc.

	if forceFetch || time.Now().After(i.expires) {
		if time.Since(i.checked) < time.Minute {
			return "", nil, errors.New("TODO capture original err")
		}
		if err := i.fetchConfig(ctx); err != nil {
			return "", nil, err
		}
		//i.checked = time.Now() // TODO(cbro): implement rate limiting.
	}

	if i.dbConfig == nil || i.tlsConfig == nil {
		// TODO(cbro): probably don't need this due to i.checked above?
		return "", nil, errors.New("invalid config") // TODO(cbro): re-return error from fetchConfig.
	}

	ip, err := findIP([]string{"PRIMARY"}, i.dbConfig)
	addr = net.JoinHostPort(ip, "3307") // TODO(cbro): postgres on 5432?
	if err != nil {
		return "", nil, err
	}
	return addr, i.tlsConfig, nil
}

func findIP(acceptedTypes []string, dbConfig *sqladmin.DatabaseInstance) (addr string, err error) {
	for _, wantType := range acceptedTypes {
		for _, instanceAddr := range dbConfig.IpAddresses {
			if strings.ToUpper(instanceAddr.Type) == strings.ToUpper(wantType) {
				return instanceAddr.IpAddress, nil
			}
		}
	}
	return "", errors.New("could not find suitable address type") // TODO(cbro): more detail in error.
}

// i.mu must be held by the caller
func (i *dbInstance) fetchConfig(ctx context.Context) error {
	// TODO(cbro): implement retries.
	dbConfig, err := i.client.api.Instances.Get(i.project, i.name).Context(ctx).Do()
	if err != nil {
		return err
	}
	// TODO(cbro): verify region, SECOND_GEN, presence of IP address, etc.
	serverCert, err := parseCert(dbConfig.ServerCaCert.Cert)
	if err != nil {
		return fmt.Errorf("could not parse server cert: %v", err)
	}
	serverCerts := x509.NewCertPool()
	serverCerts.AddCert(serverCert)

	// TODO(cbro): implement retries.
	certResp, err := i.client.api.SslCerts.CreateEphemeral(i.project, i.name, &sqladmin.SslCertsCreateEphemeralRequest{
		PublicKey: i.client.publicKeyPem,
	}).Context(ctx).Do()
	if err != nil {
		return err
	}

	clientCert, err := parseCert(certResp.Cert)
	if err != nil {
		return fmt.Errorf("could not parse client cert: %v", err)
	}

	serverName := i.project + ":" + i.name
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{clientCert.Raw},
				PrivateKey:  i.client.privateKey,
				Leaf:        clientCert,
			},
		},
		RootCAs: serverCerts,

		// We need to set InsecureSkipVerify to true due to
		// https://github.com/GoogleCloudPlatform/cloudsql-proxy/issues/194
		// https://tip.golang.org/doc/go1.11#crypto/x509
		//
		// Since we have a secure channel to the Cloud SQL API which we use to retrieve the
		// certificates, we instead need to implement our own VerifyPeerCertificate function
		// that will verify that the certificate is OK.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("need cert")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("VerifyPeerCertificate: %v", err)
			}
			if _, err = cert.Verify(x509.VerifyOptions{Roots: serverCerts}); err != nil {
				return fmt.Errorf("Verify: %v", err)
			}
			if cert.Subject.CommonName != serverName {
				return fmt.Errorf("certificate had CN %q, expected %q", cert.Subject.CommonName, serverName)
			}
			return nil
		},
	}

	i.dbConfig = dbConfig
	i.tlsConfig = tlsConfig
	i.expires = clientCert.NotAfter
	return nil
}

func parseCert(pemCert string) (*x509.Certificate, error) {
	bl, _ := pem.Decode([]byte(pemCert))
	if bl == nil {
		return nil, errors.New("invalid PEM: " + pemCert)
	}
	return x509.ParseCertificate(bl.Bytes)
}

func (i *dbInstance) tryDial(ctx context.Context, addr string, tlsConfig *tls.Config) (net.Conn, error) {
	dialer := defaultDialer.DialContext // TODO(cbro): make configurable on Client.

	conn, err := dialer(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	wrappedConn := &connWrapper{Conn: tlsConn}

	i.mu.Lock()
	i.conns = append(i.conns, wrappedConn)
	i.mu.Unlock()

	return wrappedConn, nil
}

// connWrapper wraps a net.Conn and provides some stats on when it was last
// read/written to and whether the conn looks closed (i.e., if io.EOF has been
// seen.)
type connWrapper struct {
	net.Conn

	mu        sync.Mutex
	lastRead  time.Time
	lastWrite time.Time
	closed    bool // EOF seen
}

func (c *connWrapper) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	c.mu.Lock()
	c.lastRead = time.Now()
	if err == io.EOF {
		c.closed = true
	}
	c.mu.Unlock()
	return
}

func (c *connWrapper) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	c.mu.Lock()
	c.lastWrite = time.Now()
	if err == io.EOF {
		c.closed = true
	}
	c.mu.Unlock()
	return
}

func (c *connWrapper) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Conn.Close()
}
