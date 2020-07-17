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

	1a. Pull and run the Postgres Docker container.

		$ docker run --name some-postgres -e POSTGRES_PASSWORD=mysecretpassword -p 5432:5432 -d postgres

		At this point you can execute main() below and successfully gain a response. However, if you'd
		like to further configure postgres....

	1b. Drop into the Postgres Docker container's shell:

		$ docker exec -it some-postgres bash

	1c. Begin administering it via psql:

		$ psql -h localhost -U postgres

2. Run the Approzium authenticator:

	2a. Move into the authenticator directory:

		$ cd path/to/github.com/cyralinc/approzium/authenticator

	2b. Make a dev version of the authenticator:

		$ make dev

	2c. Seed the /path/to/github.com/cyralinc/approzium/authenticator/server/testing/secrets.yaml
		with a new line like:

		- dbhost: localhost
		  dbport: 5432
		  dbuser: postgres
		  password: mysecretpassword
		  iam_arn: arn:aws:iam::0123456789012:role/AssumableRole

	2d. Run the authenticator in dev mode.

		$ authenticator --dev

3. In another window, set up a role to assume:

	$ export TEST_ASSUMABLE_ARN=arn:aws:iam::0123456789012:role/AssumableRole

4. Run the code below:

	$ cd ../sdk/go/approzium
	$ go run examples/postgresmd5/main.go

*/
func main() {
	// Create a connection to the Approzium authenticator, because only it knows the password.
	authClient, err := approzium.NewAuthClient("localhost:6001", &approzium.Config{
		DisableTLS:      true,
		RoleArnToAssume: os.Getenv("TEST_ASSUMABLE_ARN"),
	})
	if err != nil {
		log.Fatal(err)
	}

	// Now create a Postgres connection like normal but _without_ a password included.
	// Note - we also support strings like:
	// "postgres://pqgotest:@localhost/pqgotest?sslmode=verify-full"
	dataSourceName := "user=postgres dbname=postgres host=localhost port=5432 sslmode=disable"
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
