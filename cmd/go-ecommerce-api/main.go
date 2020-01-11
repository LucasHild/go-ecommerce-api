package main

import (
	"log"

	"github.com/Lanseuo/go-ecommerce-api/pkg/api"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalln("Error loading .env file")
	}

	api.Start()
}
