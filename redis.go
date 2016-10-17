package redis

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"gopkg.in/redis.v3"

	"github.com/getlantern/golog"
	"github.com/getlantern/keyman"
)

var (
	log = golog.LoggerFor("redis")
)

// Opts provides options for configuring connectivity to Redis.
type Opts struct {
	// RedisURL is the redis instance's URL in the form
	// redis://[user:pass@host:port]. Required.
	RedisURL string

	// RedisCAFile is a path to a PEM-encoded certificate for the CA that signs
	// the redis instance's server certificate. If not supplied, only the system
	// default trusted roots will be used.
	RedisCAFile string

	// ClientPKFile is a path to a PEM-encoded private key for the client to use
	// to authenticate itself to the redis stunnel. If not supplied, no client
	// authentication is performed.
	ClientPKFile string

	// ClientCertFile is a path to a PEM-encoded certificate for the client to use
	// to authenticate itself to the redis stunnel. If not supplied, no client
	// authentication is performed.
	ClientCertFile string

	// DialTimeout caps the amount of time we're willing to wait for a TCP
	// connection. Defaults to 30 seconds.
	DialTimeout time.Duration

	// TCPKeepAlive enables TCP keepalives on the connection to Redis.
	// If set to 0, keepalives are disabled.
	TCPKeepAlive time.Duration

	// The maximum number of socket connections.
	// Default is 3 connections.
	PoolSize int
}

// NewClient obtains a redis client for the given options.
func NewClient(opts *Opts) (*redis.Client, error) {
	u, err := url.Parse(opts.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse Redis address: %s", err)
	}

	if u.Host == "" {
		return nil, fmt.Errorf("Please provide a Redis URL of the form 'redis[s]://[user:pass]@host:port[/db]'")
	}

	// Setting default PoolSize to 3.
	if opts.PoolSize == 0 {
		opts.PoolSize = 3
	}

	db := int64(0)
	if len(u.Path) > 0 {
		log.Debugf("Trying to determine database number from path: %v", u.Path)
		_, dbstring := path.Split(u.Path)
		_db, err2 := strconv.Atoi(dbstring)
		if err2 != nil {
			log.Errorf("Unable to get database number from path %v: %v", u.Path, err2)
		} else {
			db = int64(_db)
		}
	}
	log.Debugf("Using database %d", db)

	dialer := &net.Dialer{
		Timeout:   opts.DialTimeout,
		KeepAlive: opts.TCPKeepAlive,
	}
	if dialer.Timeout == 0 {
		dialer.Timeout = 30 * time.Second
		log.Debugf("Defaulted dial timeout to %v", dialer.Timeout)
	}

	dialFunc := func() (net.Conn, error) {
		return dialer.Dial("tcp", u.Host)
	}

	if strings.EqualFold(u.Scheme, "rediss") {
		log.Debug("Using encrypted connection to Redis")
		tlsConfig := &tls.Config{
			ClientSessionCache: tls.NewLRUClientSessionCache(1000),
		}

		if opts.RedisCAFile == "" {
			log.Debugf("Not using custom Redis CA")
		} else {
			log.Debugf("Adding custom Redis CA from: %v", opts.RedisCAFile)
			cert, err2 := keyman.LoadCertificateFromFile(opts.RedisCAFile)
			if err2 != nil {
				return nil, fmt.Errorf("Unable to load RedisCAFile: %v", err2)
			}
			tlsConfig.RootCAs = cert.PoolContainingCert()
		}

		if opts.ClientPKFile == "" || opts.ClientCertFile == "" {
			log.Debug("Not enabling client TLS authentication")
		} else {
			log.Debugf("Enabling client TLS authentication using pk %v and cert %v", opts.ClientPKFile, opts.ClientCertFile)
			cert, err2 := tls.LoadX509KeyPair(opts.ClientCertFile, opts.ClientPKFile)
			if err2 != nil {
				return nil, fmt.Errorf("Unable to load Client certificate/key pair: %v", err2)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		dialFunc = func() (net.Conn, error) {
			return tls.DialWithDialer(dialer, "tcp", u.Host, tlsConfig)
		}
	}

	opt := redis.Options{
		Dialer:   dialFunc,
		DB:       db,
		PoolSize: opts.PoolSize,
	}
	if u.User != nil {
		redisPass, _ := u.User.Password()
		opt.Password = redisPass
	}

	return redis.NewClient(&opt), nil
}
