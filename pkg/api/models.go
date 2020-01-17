package api

import (
	"errors"
	"math"
	"regexp"

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
	Password         string `json:"-"`
	Token            string `json:"token"`
	GoogleUserID     string `json:"-" bson:"google_user_id"`
}

func (a Account) validate() error {
	emailRe := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	if !emailRe.MatchString(a.Email) {
		return errors.New("The email address is invalid")
	}

	if len(a.Password) < 8 {
		return errors.New("The password has to have at least 8 characters")
	}

	return nil
}

// Product is a sellable element
type Product struct {
	mgm.DefaultModel `bson:",inline"`
	Title            string  `json:"title"`
	Price            float64 `json:"price"`
	CreatedBy        string  `json:"created_by"`
}

func (p Product) validate() error {
	if len(p.Title) < 5 {
		return errors.New("The title has to have at leat 5 characters")
	}

	if p.Price != math.Round(p.Price*100)/100 {
		return errors.New("The price has to many decimal places")
	}

	return nil
}
