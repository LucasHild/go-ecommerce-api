package api

import (
	"net/http"
	"os"
)

var config Config = Config{}

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
	googleOauthClientID     string
	googleOauthClientSecret string
}

func (c *Config) load() {
	c.secretKey = []byte(os.Getenv("SECRET_KEY"))
	c.sessionKey = []byte(os.Getenv("SESSION_KEY"))
	c.googleOauthClientID = os.Getenv("GOOGLE_OAUTH_CLIENT_ID")
	c.googleOauthClientSecret = os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET")
}
