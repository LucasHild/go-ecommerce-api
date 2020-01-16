package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"

	"github.com/Kamva/mgm"
	"github.com/globalsign/mgo/bson"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type key int

const (
	contextKeyUserID key = iota
)

var cookieStore = sessions.NewCookieStore(config.sessionKey)

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
		RespondWithMessage(w, "An error occurred")
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
		RespondWithMessage(w, "An error occurred")
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

// AuthGoogleLogin redirects user to Google login page
func AuthGoogleLogin(w http.ResponseWriter, r *http.Request) {
	state := randToken()

	session, _ := cookieStore.Get(r, "google_state")
	session.Values["google_state"] = state
	err := session.Save(r, w)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		RespondWithMessage(w, "An error occurred")
		return
	}

	redirectURL := googleOauthConf().AuthCodeURL(state)

	http.Redirect(w, r, redirectURL, 302)
}

// AuthGoogleRedirect handles redirect from Google and signs in user
func AuthGoogleRedirect(w http.ResponseWriter, r *http.Request) {
	session, _ := cookieStore.Get(r, "google_state")
	retrievedState := session.Values["google_state"]

	if retrievedState != r.URL.Query().Get("state") {
		w.WriteHeader(http.StatusUnauthorized)
		RespondWithMessage(w, "Invalid session state")
		return
	}

	userData, err := getUserDataFromGoogle(r.URL.Query().Get("code"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println(err)
		RespondWithMessage(w, "An error occurred")
		return
	}

	fmt.Println(userData)

	RespondWithMessage(w, "Done")
}

func googleOauthConf() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     config.googleOauthClientID,
		ClientSecret: config.googleOauthClientSecret,
		RedirectURL:  "http://127.0.0.1:8080/auth/google/redirect",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
}

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

type googleUserData struct {
	ID    string `json:"sub"`
	Email string `json:"email"`
}

func getUserDataFromGoogle(code string) (googleUserData, error) {
	googleConfig := googleOauthConf()
	tok, err := googleConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		return googleUserData{}, err
	}

	client := googleConfig.Client(oauth2.NoContext, tok)
	content, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return googleUserData{}, err
	}

	defer content.Body.Close()

	var userData googleUserData

	err = json.NewDecoder(content.Body).Decode(&userData)
	if err != nil {
		return googleUserData{}, err
	}

	return userData, nil
}
