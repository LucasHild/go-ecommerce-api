package api

import (
	"github.com/Kamva/mgm"
	"github.com/dgrijalva/jwt-go"
)

type Token struct {
	UserID uint
	jwt.StandardClaims
}

type Account struct {
	mgm.DefaultModel `bson:",inline"`
	Email            string `json:"email"`
	Password         string `json:"password"`
	Token            string `json:"-"`
}
