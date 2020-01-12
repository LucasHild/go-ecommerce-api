package api

import (
	"github.com/Kamva/mgm"
	"github.com/dgrijalva/jwt-go"
)

// TokenClaims is used to create JWT token
type TokenClaims struct {
	UserID string
	jwt.StandardClaims
}

// Account is used to store user information
type Account struct {
	mgm.DefaultModel `bson:",inline"`
	Email            string `json:"email"`
	Password         string `json:"password"`
	Token            string `json:"token"`
}

// Product is a sellable element
type Product struct {
	mgm.DefaultModel `bson:",inline"`
	Title            string  `json:"title"`
	Price            float64 `json:"price"`
	CreatedBy        string  `json:"created_by"`
}
