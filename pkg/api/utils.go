package api

import (
	"encoding/json"
	"net/http"
	"os"
)

var config Config = Config{}

func RespondWithMessage(w http.ResponseWriter, message string) {
	data := map[string]interface{}{"message": message}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

type Config struct {
	secretKey []byte
}

func (c *Config) load() {
	c.secretKey = []byte(os.Getenv("SECRET_KEY"))
}
