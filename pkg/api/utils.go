package api

import (
	"encoding/json"
	"net/http"
	"os"
)

var config Config = Config{}

// RespondWithMessage sends message string to response writer
func RespondWithMessage(w http.ResponseWriter, message string) {
	data := map[string]interface{}{"message": message}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
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
