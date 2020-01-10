package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Kamva/mgm"
	"github.com/globalsign/mgo/bson"
	"golang.org/x/crypto/bcrypt"
)

// JWTAuthentication is a middleware that checks authentication
// https://medium.com/@adigunhammedolalekan/build-and-deploy-a-secure-rest-api-with-go-postgresql-jwt-and-gorm-6fadf3da505b
func JWTAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHeader := r.Header.Get("Authorization")

		if tokenHeader == "" {
			w.WriteHeader(http.StatusForbidden)
			RespondWithMessage(w, "Missing auth token")
			return
		}

		splitted := strings.Split(tokenHeader, " ")
		if len(splitted) != 2 {
			w.WriteHeader(http.StatusForbidden)
			RespondWithMessage(w, "Invalid auth token")
			return
		}

		token := splitted[1]
		fmt.Println("Token", token)

		ctx := context.WithValue(r.Context(), "user", "EXAMPLE_USER_ID")
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
		return
	})
}

func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	var account Account

	err := json.NewDecoder(r.Body).Decode(&account)
	if err != nil {
		log.Fatalln("Error unmarshalling data", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	SignUp(account.Email, account.Password, w)
}

func SignUp(email string, password string, w http.ResponseWriter) {
	if len(password) < 8 {
		w.WriteHeader(http.StatusBadRequest)
		RespondWithMessage(w, "The password has to have at least 8 characters")
		return
	}
	// TODO: Email validation

	var existingAccounts = []Account{}
	err := mgm.Coll(&Account{}).SimpleFind(&existingAccounts, bson.M{"email": email})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		RespondWithMessage(w, "An error occured")
		return
	}
	if len(existingAccounts) != 0 {
		w.WriteHeader(http.StatusForbidden)
		RespondWithMessage(w, "Account with this email already exists")
		return
	}

	account := Account{
		Email: email,
	}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	account.Password = string(hashedPassword)

	err = mgm.Coll(&account).Create(&account)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		RespondWithMessage(w, "Error creating account")
		return
	}

	RespondWithMessage(w, "Successfully created account")
}
