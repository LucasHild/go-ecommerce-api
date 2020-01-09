package api

import (
	"github.com/Kamva/mgm"
)

// Product is a sellable element
type Product struct {
	mgm.DefaultModel `bson:",inline"`
	Title            string  `json:"title"`
	Price            float64 `json:"price"`
}
