package api

import (
	"net/http"
	"os"
)

// RespondWithMessage sends message string to response writer
func RespondWithMessage(w http.ResponseWriter, status int, message string) {
	rnd.JSON(w, status, map[string]string{
		"message": message,
	})
}

// Config stores application configuration
type Config struct {
	secretKey               []byte
	sessionKey              []byte
	mongoDBURI              string
	mongoDBDB               string
	googleOauthClientID     string
	googleOauthClientSecret string
}

func getConfig() Config {
	return Config{
		secretKey:               []byte(os.Getenv("SECRET_KEY")),
		sessionKey:              []byte(os.Getenv("SESSION_KEY")),
		googleOauthClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		googleOauthClientSecret: os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		mongoDBURI:              os.Getenv("MONGODB_URI"),
		mongoDBDB:               os.Getenv("MONGODB_DB"),
	}
}
