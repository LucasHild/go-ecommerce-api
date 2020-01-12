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
	secretKey []byte
}

func (c *Config) load() {
	c.secretKey = []byte(os.Getenv("SECRET_KEY"))
}
