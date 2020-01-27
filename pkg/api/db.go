package api

import (
	"log"

	"github.com/Kamva/mgm"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func connectToDB() {
	err := mgm.SetDefaultConfig(nil, config.mongoDBDB, options.Client().ApplyURI(config.mongoDBURI))
	if err != nil {
		log.Fatalln("Can't connect to database", err)
	}
}
