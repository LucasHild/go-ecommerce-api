package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"github.com/Kamva/mgm"
	"github.com/globalsign/mgo/bson"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
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
			RespondWithMessage(w, http.StatusForbidden, "Missing auth token")
			return
		}

		splitted := strings.Split(tokenHeader, " ")
		if len(splitted) != 2 {
			RespondWithMessage(w, http.StatusForbidden, "Malformed auth token")
			return
		}

		tokenString := splitted[1]
		tokenClaims := &TokenClaims{}
		token, err := jwt.ParseWithClaims(tokenString, tokenClaims, func(token *jwt.Token) (interface{}, error) {
			return config.secretKey, nil
		})
		if err != nil {
			RespondWithMessage(w, http.StatusForbidden, "Malformed auth token")
			return
		}

		if !token.Valid {
			RespondWithMessage(w, http.StatusForbidden, "Invalid auth token")
			return
		}

		// TODO: Check whether user still exists

		ctx := context.WithValue(r.Context(), contextKeyUserID, tokenClaims.UserID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
		return
	})
}

type UserCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (u UserCredentials) validate() error {
	emailRe := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	if !emailRe.MatchString(u.Email) {
		return errors.New("The email address is invalid")
	}

	if len(u.Password) < 8 {
		return errors.New("The password has to have at least 8 characters")
	}

	return nil
}

// SignUpHandler handles user sign up
func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	var credentials UserCredentials

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		RespondWithMessage(w, http.StatusBadRequest, "Invalid JSON Payload")
		return
	}

	err = credentials.validate()
	if err != nil {
		RespondWithMessage(w, http.StatusBadRequest, err.Error())
		return
	}

	signUp(credentials.Email, credentials.Password, w)
}

func signUp(email string, password string, w http.ResponseWriter) {
	var existingAccounts []Account

	err := mgm.Coll(&Account{}).SimpleFind(&existingAccounts, bson.M{"email": email})
	if err != nil {
		log.Println(err)
		RespondWithMessage(w, http.StatusInternalServerError, "An error occurred")
		return
	}
	if len(existingAccounts) != 0 {
		RespondWithMessage(w, http.StatusForbidden, "Account with this email already exists")
		return
	}

	account := Account{
		Email: email,
	}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	account.Password = string(hashedPassword)

	err = mgm.Coll(&account).Create(&account)
	if err != nil {
		RespondWithMessage(w, http.StatusForbidden, "Error creating account")
		return
	}

	RespondWithMessage(w, http.StatusOK, "Successfully created account")
}

// LoginHandler handles user login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Prevent login from Google Accounts
	var credentials UserCredentials

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		RespondWithMessage(w, http.StatusBadRequest, "Invalid JSON Payload")
		return
	}

	account, token, err := login(credentials.Email, credentials.Password, w)
	if err != nil {
		return
	}

	rnd.JSON(w, http.StatusOK, map[string]interface{}{
		"account": account,
		"token":   token,
	})
}

func login(email string, password string, w http.ResponseWriter) (Account, string, error) {
	var account Account

	err := mgm.Coll(&account).First(bson.M{"email": email}, &account)
	if err != nil {
		RespondWithMessage(w, http.StatusForbidden, "Account doesn't exist. Please try again")
		return Account{}, "", err
	}

	err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		RespondWithMessage(w, http.StatusForbidden, "Invalid login credentials. Please try again")
		return Account{}, "", err
	}

	token := createToken(account)
	if err != nil {
		log.Println(err)
		RespondWithMessage(w, http.StatusInternalServerError, "An error occurred")
		return Account{}, "", err
	}
	return account, token, nil
}

func createToken(account Account) string {
	tokenClaims := &TokenClaims{UserID: account.ID.Hex()}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tokenClaims)
	tokenString, _ := token.SignedString(config.secretKey)

	return tokenString
}

// AuthGoogleLogin redirects user to Google login page
func AuthGoogleLogin(w http.ResponseWriter, r *http.Request) {
	state := randToken()

	session, _ := cookieStore.Get(r, "google_state")
	session.Values["google_state"] = state
	err := session.Save(r, w)
	if err != nil {
		log.Println(err)
		RespondWithMessage(w, http.StatusInternalServerError, "An error occurred")
		return
	}

	redirectURL := googleOauthConf.AuthCodeURL(state)

	http.Redirect(w, r, redirectURL, 302)
}

// AuthGoogleRedirect handles redirect from Google and signs in user
func AuthGoogleRedirect(w http.ResponseWriter, r *http.Request) {
	session, _ := cookieStore.Get(r, "google_state")
	retrievedState := session.Values["google_state"]

	if retrievedState != r.URL.Query().Get("state") {
		RespondWithMessage(w, http.StatusUnauthorized, "Invalid session state")
		return
	}

	userData, err := getUserDataFromGoogle(r.URL.Query().Get("code"))
	if err != nil {
		log.Println("Error fetching user data from Google:", err)
		RespondWithMessage(w, http.StatusInternalServerError, "An error occurred")
		return
	}

	// TODO: Prevent duplicate accounts with same mail address

	var existingAccounts = []Account{}
	err = mgm.Coll(&Account{}).SimpleFind(&existingAccounts, bson.M{"google_user_id": userData.ID})
	if err != nil {
		log.Println(err)
		RespondWithMessage(w, http.StatusInternalServerError, "An error occurred")
		return
	}
	isNewUser := len(existingAccounts) == 0

	var account Account
	if isNewUser {
		account = Account{
			Email:        userData.Email,
			GoogleUserID: userData.ID,
		}

		err = mgm.Coll(&account).Create(&account)
		if err != nil {
			RespondWithMessage(w, http.StatusForbidden, "Error creating account")
			return
		}
		RespondWithMessage(w, http.StatusOK, "Successfully created account")
	} else {
		account = existingAccounts[0]

	}

	token := createToken(account)
	rnd.JSON(w, http.StatusOK, map[string]interface{}{
		"new_user": isNewUser,
		"user":     account,
		"token":    token,
	})
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
	tok, err := googleOauthConf.Exchange(oauth2.NoContext, code)
	if err != nil {
		return googleUserData{}, err
	}

	client := googleOauthConf.Client(oauth2.NoContext, tok)
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
