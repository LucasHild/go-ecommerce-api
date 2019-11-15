package api

import "github.com/go-bongo/bongo"

type Product struct {
	bongo.DocumentBase `bson:",inline"`
	Title              string  `json:"title"`
	Price              float64 `json:"price"`
}
