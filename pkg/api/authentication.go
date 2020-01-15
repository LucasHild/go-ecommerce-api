package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"github.com/Kamva/mgm"
	"github.com/globalsign/mgo/bson"
	"golang.org/x/crypto/bcrypt"
)

type key int

const (
	contextKeyUserID key = iota
)

// JWTAuthentication is a middleware that checks authentication
func JWTAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type Route struct {
			Path   string
			Method string
		}

		tokenHeader := r.Header.Get("Authorization")

		if tokenHeader == "" {
			w.WriteHeader(http.StatusForbidden)
			RespondWithMessage(w, "Missing auth token")
			return
		}

		splitted := strings.Split(tokenHeader, " ")
		if len(splitted) != 2 {
			w.WriteHeader(http.StatusForbidden)
			RespondWithMessage(w, "Malformed auth token")
			return
		}

		tokenString := splitted[1]
		tokenClaims := &TokenClaims{}
		token, err := jwt.ParseWithClaims(tokenString, tokenClaims, func(token *jwt.Token) (interface{}, error) {
			return config.secretKey, nil
		})
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			RespondWithMessage(w, "Malformed auth token")
			return
		}

		if !token.Valid {
			w.WriteHeader(http.StatusForbidden)
			RespondWithMessage(w, "Invalid auth token")
			return
		}

		// TODO: Check whether user still exists

		ctx := context.WithValue(r.Context(), contextKeyUserID, tokenClaims.UserID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
		return
	})
}

// SignUpHandler handles user sign up
func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	var account Account

	err := json.NewDecoder(r.Body).Decode(&account)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		RespondWithMessage(w, "Invalid JSON Payload")
		return
	}

	err = account.validate()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		RespondWithMessage(w, err.Error())
		return
	}

	signUp(account.Email, account.Password, w)
}

func signUp(email string, password string, w http.ResponseWriter) {
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

// LoginHandler handles user login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var account Account

	err := json.NewDecoder(r.Body).Decode(&account)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		RespondWithMessage(w, "Invalid JSON Payload")
		return
	}

	account, err = login(account.Email, account.Password, w)
	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	err = json.NewEncoder(w).Encode(account)
	if err != nil {
		log.Fatalln("Error marshalling data", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func login(email string, password string, w http.ResponseWriter) (Account, error) {
	var account Account

	err := mgm.Coll(&account).First(bson.M{"email": email}, &account)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		RespondWithMessage(w, "Account doesn't exist. Please try again")
		return Account{}, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		w.WriteHeader(http.StatusForbidden)
		RespondWithMessage(w, "Invalid login credentials. Please try again")
		return Account{}, err
	}

	err = createToken(&account)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		RespondWithMessage(w, "An error occured")
		return Account{}, err
	}
	return account, nil
}

func createToken(account *Account) error {
	account.Password = ""

	tokenClaims := &TokenClaims{UserID: account.ID.Hex()}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tokenClaims)
	tokenString, _ := token.SignedString([]byte(os.Getenv("SECRET_KEY")))

	account.Token = tokenString
	return nil
}
