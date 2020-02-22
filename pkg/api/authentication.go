package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
func (s *Server) JWTAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHeader := r.Header.Get("Authorization")
		if tokenHeader == "" {
			rnd.JSON(w, http.StatusForbidden, UserError{http.StatusForbidden, "Missing auth token", nil})
			return
		}

		splitted := strings.Split(tokenHeader, " ")
		if len(splitted) != 2 {
			rnd.JSON(w, http.StatusForbidden, UserError{http.StatusForbidden, "Malformed auth token", nil})
			return
		}

		tokenString := splitted[1]
		tokenClaims := &TokenClaims{}
		token, err := jwt.ParseWithClaims(tokenString, tokenClaims, func(token *jwt.Token) (interface{}, error) {
			return s.config.secretKey, nil
		})
		if err != nil {
			rnd.JSON(w, http.StatusForbidden, UserError{http.StatusForbidden, "Malformed auth token", nil})
			return
		}

		if !token.Valid {
			rnd.JSON(w, http.StatusForbidden, UserError{http.StatusForbidden, "Invalid auth token", nil})
			return
		}

		var user User
		err = mgm.Coll(&User{}).FindByID(tokenClaims.UserID, &user)
		if err != nil {
			rnd.JSON(w, http.StatusForbidden, UserError{http.StatusForbidden, "This user doesn't exist", nil})
			return
		}

		ctx := context.WithValue(r.Context(), contextKeyUserID, tokenClaims.UserID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
		return
	})
}

// UserCredentials are used for signup and login
type UserCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (u UserCredentials) validate() error {
	emailRe := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	if !emailRe.MatchString(u.Email) {
		return UserError{http.StatusBadRequest, "The email address is invalid", nil}
	}

	if len(u.Password) < 8 {
		return UserError{http.StatusBadRequest, "The password has to have at least 8 characters", nil}
	}

	return nil
}

// SignUpHandler handles user sign up
func (s *Server) SignUpHandler(w http.ResponseWriter, r *http.Request) error {
	var credentials UserCredentials

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		return UserError{http.StatusBadRequest, "Invalid JSON Payload", err}
	}

	err = credentials.validate()
	if err != nil {
		return err
	}

	user, err := signUp(credentials.Email, credentials.Password)
	if err != nil {
		return err
	}

	rnd.JSON(w, http.StatusOK, map[string]interface{}{
		"user": user,
	})
	return nil
}

func signUp(email string, password string) (user User, err error) {
	var existingUsers []User

	err = mgm.Coll(&User{}).SimpleFind(&existingUsers, bson.M{"email": email})
	if err != nil {
		return user, err
	}
	if len(existingUsers) != 0 {
		return user, UserError{http.StatusForbidden, "User with this email already exists", err}
	}

	user = User{
		Email: email,
	}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	user.Password = string(hashedPassword)

	err = mgm.Coll(&user).Create(&user)
	if err != nil {
		return user, err
	}

	return user, nil
}

// LoginHandler handles user login
func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request) error {
	// TODO: Prevent login from Google Users
	var credentials UserCredentials

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		return UserError{http.StatusBadRequest, "Invalid JSON Payload", err}
	}

	user, token, err := login(credentials.Email, credentials.Password, s)
	if err != nil {
		return err
	}

	rnd.JSON(w, http.StatusOK, map[string]interface{}{
		"user":  user,
		"token": token,
	})
	return nil
}

func login(email string, password string, s *Server) (user User, token string, err error) {
	err = mgm.Coll(&user).First(bson.M{"email": email}, &user)
	if err != nil {
		return User{}, "", UserError{http.StatusForbidden, "User doesn't exist", err}
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		return User{}, "", UserError{http.StatusForbidden, "Invalid login credentials", err}
	}

	token = createToken(user, s.config.secretKey)
	if err != nil {
		return User{}, "", err
	}
	return user, token, nil
}

func createToken(user User, secretKey []byte) string {
	tokenClaims := &TokenClaims{UserID: user.ID.Hex()}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tokenClaims)
	tokenString, _ := token.SignedString(secretKey)

	return tokenString
}

// AuthGoogleLogin redirects user to Google login page
func (s *Server) AuthGoogleLogin(w http.ResponseWriter, r *http.Request) {
	state := randToken()

	session, _ := s.cookieStore.Get(r, "google_state")
	session.Values["google_state"] = state
	err := session.Save(r, w)
	if err != nil {
		log.Println(err)
		RespondWithMessage(w, http.StatusInternalServerError, "An error occurred")
		return
	}

	redirectURL := s.googleOauthConf.AuthCodeURL(state)

	http.Redirect(w, r, redirectURL, 302)
}

// AuthGoogleRedirect handles redirect from Google and signs in user
func (s *Server) AuthGoogleRedirect(w http.ResponseWriter, r *http.Request) {
	session, _ := s.cookieStore.Get(r, "google_state")
	retrievedState := session.Values["google_state"]

	if retrievedState != r.URL.Query().Get("state") {
		RespondWithMessage(w, http.StatusUnauthorized, "Invalid session state")
		return
	}

	userData, err := getUserDataFromGoogle(r.URL.Query().Get("code"), s.googleOauthConf)
	if err != nil {
		log.Println("Error fetching user data from Google:", err)
		RespondWithMessage(w, http.StatusInternalServerError, "An error occurred")
		return
	}

	// TODO: Prevent duplicate users with same mail address

	var existingUsers = []User{}
	err = mgm.Coll(&User{}).SimpleFind(&existingUsers, bson.M{"google_user_id": userData.ID})
	if err != nil {
		log.Println(err)
		RespondWithMessage(w, http.StatusInternalServerError, "An error occurred")
		return
	}
	isNewUser := len(existingUsers) == 0

	var user User
	if isNewUser {
		user = User{
			Email:        userData.Email,
			GoogleUserID: userData.ID,
		}

		err = mgm.Coll(&user).Create(&user)
		if err != nil {
			RespondWithMessage(w, http.StatusForbidden, "Error creating user")
			return
		}
		RespondWithMessage(w, http.StatusOK, "Successfully created user")
	} else {
		user = existingUsers[0]

	}

	token := createToken(user, s.config.secretKey)
	rnd.JSON(w, http.StatusOK, map[string]interface{}{
		"new_user": isNewUser,
		"user":     user,
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

func getUserDataFromGoogle(code string, oauth *oauth2.Config) (googleUserData, error) {
	tok, err := oauth.Exchange(oauth2.NoContext, code)
	if err != nil {
		return googleUserData{}, err
	}

	client := oauth.Client(oauth2.NoContext, tok)
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
