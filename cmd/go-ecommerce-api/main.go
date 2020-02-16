package main

import "github.com/Lanseuo/go-ecommerce-api/pkg/api"

func main() {
	server := api.Server{}
	server.Start()
}
