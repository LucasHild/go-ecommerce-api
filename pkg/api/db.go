package api

import (
	"log"

	"github.com/Kamva/mgm"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func connectToDB() {
	err := mgm.SetDefaultConfig(nil, "go-ecommerce-api", options.Client().ApplyURI("mongodb://localhost"))
	if err != nil {
		log.Fatalln("Can't connect to database", err)
	}
}
