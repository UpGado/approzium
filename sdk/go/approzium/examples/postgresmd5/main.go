package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cyralinc/approzium/sdk/go/approzium"
)

/*

QUICK TESTING

1. Create a test database to run this against:

docker run --name some-postgres -e POSTGRES_PASSWORD=mysecretpassword -p 5432:5432 -d postgres

At this point you can execute main() below and successfully gain a response. However, if you'd
like to further configure postgres....

2. Drop into the Postgres Docker container's shell:

docker exec -it some-postgres bash

3. Begin administering it via psql:

psql -h localhost -U postgres

*/
func main() {
	// Create a connection to the Approzium authenticator, because only it knows the password.
	authClient, err := approzium.NewAuthClient("authenticator:6001", &approzium.Config{
		DisableTLS:      true,
		RoleArnToAssume: os.Getenv("TEST_ASSUMABLE_ARN"),
	})
	if err != nil {
		log.Fatal(err)
	}

	// Now create a Postgres connection like normal but _without_ a password included.
	// Note - we also support strings like:
	// "postgres://pqgotest:@localhost/pqgotest?sslmode=verify-full"
	dataSourceName := "user=postgres password=mysecretpassword dbname=postgres host=localhost port=5432 sslmode=disable"
	db, err := authClient.Open("postgres", dataSourceName)
	if err != nil {
		log.Fatal(err)
	}
	rows, err := db.Query("SELECT 1")
	if err != nil {
		log.Fatal(err)
	}
	if rows.Next() {
		fmt.Println("successfully got a result")
	} else {
		fmt.Println("received nothing")
	}
}
