package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cyralinc/approzium/sdk/go/approzium/identity"
	log "github.com/sirupsen/logrus"
)

func main() {
	handler, err := identity.NewHandler(log.New(), os.Getenv("TEST_ASSUMABLE_ARN"))
	if err != nil {
		log.Fatal(err)
	}
	proof := handler.Retrieve()
	b, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("proof: %s\n", b)
}
