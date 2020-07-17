package approzium

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	pb "github.com/cyralinc/approzium/authenticator/server/protos"
	"github.com/cyralinc/approzium/sdk/go/approzium/identity"
	"github.com/cyralinc/pq"
	_ "github.com/cyralinc/pq"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const defaultPostgresPort = "5432"

type Config struct {
	// Logger is optional. It's available for you to set in case you'd like to
	// customize it. If not set, it defaults to INFO level and text output.
	Logger *log.Logger

	// TODO implement TLS
	// Set to true
	DisableTLS    bool
	PathToTLSCert string
	PathToTLSKey  string

	// RoleArnToAssume is an optional field. Simply don't set it if you'd prefer
	// not to assume any role when AWS is used to prove an identity. If not supplied,
	// the enclosing environment's identity will be used. This is mostly provided
	// for convenience of testing.
	RoleArnToAssume string
}

// Examples of grpcAddr:
// 		- authenticator:6001 (in Docker networking where http(s) can be dropped)
// 		- http://localhost:6001
// 		- https://localhost:6001
// 		- https://somewhere:6001
func NewAuthClient(grpcAddress string, config *Config) (*AuthClient, error) {
	if config.Logger == nil {
		config.Logger = log.New()
		config.Logger.SetLevel(log.InfoLevel)
		config.Logger.SetFormatter(&log.TextFormatter{
			FullTimestamp:          true,
			DisableLevelTruncation: true,
			PadLevelText:           true,
		})
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
	if strings.Contains(strings.ToLower(dataSourceName), "password") {
		return nil, errors.New("approzium is for passwordless authentication and uses your identity as your password, please remove the password field from your connection string")
	}

	dbHost := ""
	dbPort := ""

	// Add a placeholder password of "unknown" so the code won't error on an empty value.
	if strings.HasPrefix(dataSourceName, "postgres://") {
		// Convert strings like:
		//		"postgres://pqgotest:@localhost/pqgotest?sslmode=verify-full"
		// to:
		//		"postgres://pqgotest:unknown@localhost/pqgotest?sslmode=verify-full"
		fields := strings.Split(dataSourceName, "@")
		if len(fields) != 2 {
			return nil, fmt.Errorf(`expected connection string like 'postgres://pqgotest:@localhost/pqgotest?sslmode=verify-full' but received %q`, dataSourceName)
		}
		dataSourceName = fields[0] + "unknown@" + fields[1]
		u, err := url.Parse(dataSourceName)
		if err != nil {
			return nil, err
		}
		dbHost = u.Host
		dbPort = u.Port()
	} else {
		dataSourceName += " password=unknown"

		// Extract the host and port from a string like:
		// 		"user=postgres password=mysecretpassword dbname=postgres host=localhost port=5432 sslmode=disable"
		fields := strings.Split(dataSourceName, " ")
		for _, field := range fields {
			if dbHost != "" && dbPort != "" {
				break
			}
			kv := strings.Split(field, "=")
			if len(kv) != 2 {
				return nil, fmt.Errorf("expected one = per group, but received %s", field)
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
		return nil, fmt.Errorf("unable to parse host from %s", dataSourceName)
	}
	if dbPort == "" {
		a.config.Logger.Warnf("unable to parse port from %s, defaulting to %s", dataSourceName, defaultPostgresPort)
		dbPort = defaultPostgresPort
	}

	proof := a.identityHandler.Retrieve()
	conn, err := grpc.Dial(a.grpcAddress, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	authClient := pb.NewAuthenticatorClient(conn)

	// In case the client is being used on multiple threads, we need to
	// lock while replacing and using the hash function so we don't
	// create a race condition.
	a.hashFuncLock.Lock()
	defer a.hashFuncLock.Unlock()
	pq.GetMD5Hash = func(user, password, salt string) (string, error) {
		resp, err := authClient.GetPGMD5Hash(context.Background(), &pb.PGMD5HashRequest{
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
	return sql.Open(driverName, dataSourceName)
}
