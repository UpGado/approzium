package approzium

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	srvId "github.com/cyralinc/approzium/authenticator/server/identity"
	pb "github.com/cyralinc/approzium/authenticator/server/protos"
	"github.com/cyralinc/approzium/sdk/go/approzium/identity"
	"github.com/cyralinc/pq"
	_ "github.com/cyralinc/pq"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defaultPostgresPort = "5432"
	postgresUrlPrefix   = "postgres://"
)

var passwordIncludedErr = errors.New("approzium is for passwordless authentication and uses your identity as your password, " +
	"please remove the password field from your connection string")

// Examples of grpcAddr:
// 		- authenticator:6001
// 		- localhost:6001
// 		- somewhere:6001
// HTTPS is used unless TLS is disabled.
func NewAuthClient(grpcAddress string, config *Config) (*AuthClient, error) {
	if err := config.parse(); err != nil {
		return nil, err
	}

	identityHandler, err := identity.NewHandler(config.Logger, config.RoleArnToAssume)
	if err != nil {
		return nil, err
	}
	return &AuthClient{
		grpcAddress:     grpcAddress,
		config:          config,
		identityHandler: identityHandler,
	}, nil
}

type AuthClient struct {
	grpcAddress string
	config      *Config

	// This is used for preventing a race as we overwrite the hashing
	// func for each call.
	hashFuncLock sync.Mutex

	// This is used for caching identity for an appropriate period of time.
	identityHandler *identity.Handler
}

func (a *AuthClient) Open(driverName, dataSourceName string) (*sql.DB, error) {
	switch driverName {
	case "postgres":
		return a.handlePostgresConn(driverName, dataSourceName)
	default:
		return nil, fmt.Errorf("%s is not supported", driverName)
	}
}

func (a *AuthClient) handlePostgresConn(driverName, dataSourceName string) (*sql.DB, error) {
	dataSourceName, err := addPlaceholderPassword(dataSourceName)
	if err != nil {
		return nil, err
	}

	dbHost, dbPort, err := parseDSN(a.config.Logger, dataSourceName)
	if err != nil {
		return nil, err
	}

	proof := a.identityHandler.Retrieve()

	var conn grpc.ClientConnInterface
	if a.config.DisableTLS {
		conn, err = grpc.Dial(a.grpcAddress, grpc.WithInsecure())
		if err != nil {
			return nil, err
		}
	} else {
		creds, err := credentials.NewClientTLSFromFile(a.config.PathToClientCert, a.config.PathToClientKey)
		if err != nil {
			return nil, err
		}
		conn, err = grpc.Dial(a.grpcAddress, grpc.WithTransportCredentials(creds))
		if err != nil {
			return nil, err
		}
	}
	authClient := pb.NewAuthenticatorClient(conn)

	// In case the client is being used on multiple threads, we need to
	// lock while replacing and using the hash function so we don't
	// create a race condition.
	a.hashFuncLock.Lock()
	defer a.hashFuncLock.Unlock()
	pq.GetMD5Hash = fetchHashFromApproziumAuthenticator(authClient, proof, dbHost, dbPort)
	return sql.Open(driverName, dataSourceName)
}

type Config struct {
	// Logger is optional. It's available for you to set in case you'd like to
	// customize it. If not set, it defaults to INFO level and text output.
	Logger *log.Logger

	// Set to true to disable. TLS is enabled by default.
	DisableTLS bool

	// This client's certificate, used for proving its identity, and used by
	// the caller to encrypt communication with its public key.
	PathToClientCert string

	// This client's key, used for decrypting incoming communication that was
	// encrypted by callers using the client cert's public key.
	PathToClientKey string

	// RoleArnToAssume is an optional field. Simply don't set it if you'd prefer
	// not to assume any role when AWS is used to prove an identity. If not supplied,
	// the enclosing environment's identity will be used.
	RoleArnToAssume string
}

func (c *Config) parse() error {
	if c.Logger == nil {
		c.Logger = log.New()
		c.Logger.SetLevel(log.InfoLevel)
		c.Logger.SetFormatter(&log.TextFormatter{
			FullTimestamp:          true,
			DisableLevelTruncation: true,
			PadLevelText:           true,
		})
	}
	if !c.DisableTLS {
		if c.PathToClientCert == "" {
			return errors.New("if TLS isn't disabled, the path to the TLS client certificate must be provided")
		}
		if c.PathToClientKey == "" {
			return errors.New("if TLS isn't disabled, the path to the TLS client key must be provided")
		}
	}
	return nil
}

// addPlaceholderPassword ensures the user hasn't provided a password
// (because only the Approzium authentication server should have it),
// and then adds a placeholder password so lib/pq won't trip from not
// having anything supplied.
func addPlaceholderPassword(dataSourceName string) (string, error) {
	if !strings.HasPrefix(dataSourceName, postgresUrlPrefix) {
		// We received a string like:
		// user=postgres dbname=postgres host=localhost port=5432 sslmode=disable
		if strings.Contains(strings.ToLower(dataSourceName), "password") {
			return "", passwordIncludedErr
		}

		// Just add a password=unknown field to the end and return.
		return dataSourceName + " password=unknown", nil
	}

	// Convert strings like:
	//		"postgres://pqgotest:@localhost/pqgotest?sslmode=verify-full"
	// to:
	//		"postgres://pqgotest:unknown@localhost/pqgotest?sslmode=verify-full"
	u, err := url.Parse(dataSourceName)
	if err != nil {
		return "", err
	}
	if password, _ := u.User.Password(); password != "" {
		return "", passwordIncludedErr
	}

	fields := strings.Split(dataSourceName, "@")
	if len(fields) != 2 {
		return "", fmt.Errorf(`expected connection string like 'postgres://pqgotest:@localhost/pqgotest?sslmode=verify-full' but received %q`, dataSourceName)
	}
	return fields[0] + "unknown@" + fields[1], nil
}

func parseDSN(logger *log.Logger, dataSourceName string) (dbHost, dbPort string, err error) {
	if strings.HasPrefix(dataSourceName, postgresUrlPrefix) {
		u, err := url.Parse(dataSourceName)
		if err != nil {
			return "", "", err
		}
		// If a host and port were sent, this will initially come through as "localhost:1234"
		hostFields := strings.Split(u.Host, ":")
		dbHost = hostFields[0]
		dbPort = u.Port()
	} else {
		// Extract the host and port from a string like:
		// 		"user=postgres password=mysecretpassword dbname=postgres host=localhost port=5432 sslmode=disable"
		fields := strings.Split(dataSourceName, " ")
		for _, field := range fields {
			if dbHost != "" && dbPort != "" {
				break
			}
			kv := strings.Split(field, "=")
			if len(kv) != 2 {
				return "", "", fmt.Errorf("expected one = per group, but received %s", field)
			}
			key := kv[0]
			val := kv[1]
			if key == "host" {
				dbHost = val
				continue
			}
			if key == "port" {
				dbPort = val
				continue
			}
		}
	}

	if dbHost == "" {
		return "", "", fmt.Errorf("unable to parse host from %s", dataSourceName)
	}
	if dbPort == "" {
		logger.Warnf("unable to parse port from %s, defaulting to %s", dataSourceName, defaultPostgresPort)
		dbPort = defaultPostgresPort
	}
	return dbHost, dbPort, nil
}

func fetchHashFromApproziumAuthenticator(client pb.AuthenticatorClient, proof *srvId.Proof, dbHost, dbPort string) func(user, password, salt string) (string, error) {
	return func(user, password, salt string) (string, error) {
		resp, err := client.GetPGMD5Hash(context.Background(), &pb.PGMD5HashRequest{
			PwdRequest: &pb.PasswordRequest{
				ClientLanguage: proof.ClientLang,
				Dbhost:         dbHost,
				Dbport:         dbPort,
				Dbuser:         user,
				Aws:            proof.AwsAuth,
			},
			Salt: []byte(salt),
		})
		if err != nil {
			return "", err
		}
		return resp.Hash, nil
	}
}
