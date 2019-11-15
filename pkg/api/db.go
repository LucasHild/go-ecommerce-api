package api

import (
	"log"

	"github.com/go-bongo/bongo"
)

// DBConnection is the connection handle for the database
var DBConnection *bongo.Connection

func connectToDB() {
	config := &bongo.Config{
		ConnectionString: "localhost",
		Database:         "go-ecommerce-api",
	}

	connection, err := bongo.Connect(config)
	if err != nil {
		log.Fatalln("Can't connect to database", err)
	}
	DBConnection = connection
}
