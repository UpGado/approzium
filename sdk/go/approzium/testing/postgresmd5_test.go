package testing

import (
	"os"
	"strconv"
	"testing"

	"github.com/cyralinc/approzium/sdk/go/approzium"
	log "github.com/sirupsen/logrus"
)

func TestPostgresMD5(t *testing.T) {
	disableTLS := false
	if raw := os.Getenv("APPROZIUM_DISABLE_TLS"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			t.Fatalf("couldn't parse APPROZIUM_DISABLE_TLS %s as a bool", raw)
		}
		disableTLS = b
	}
	authClient, err := approzium.NewAuthClient("localhost:6001", &approzium.Config{
		Logger:           log.New(),
		DisableTLS:       disableTLS,
		PathToClientCert: os.Getenv("TEST_CERT_DIR") + "/client.pem",
		PathToClientKey:  os.Getenv("TEST_CERT_DIR") + "/client.key",
		RoleArnToAssume:  os.Getenv("TEST_ASSUMABLE_ARN"),
	})
	if err != nil {
		t.Fatal(err)
	}

	dataSourceName := "user=postgres dbname=postgres host=localhost port=5432 sslmode=disable"
	db, err := authClient.Open("postgres", dataSourceName)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT 1")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	if !rows.Next() {
		t.Fatal("received nothing")
	}
}
