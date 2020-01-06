package api

import (
	"encoding/json"
	"net/http"
)

func RespondWithMessage(w http.ResponseWriter, message string) {
	data := map[string]interface{}{"message": message}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
