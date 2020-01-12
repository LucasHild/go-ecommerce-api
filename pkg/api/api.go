package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

// Start the API server
func Start() error {
	fmt.Println("Connecting to db ...")
	connectToDB()
	config.load()

	router := mux.NewRouter()
	router.HandleFunc("/", HomeHandler)
	router.HandleFunc("/products", GetProductsHandler).Methods("GET")
	router.HandleFunc("/products", AddProductHandler).Methods("POST")
	router.HandleFunc("/login", LoginHandler).Methods("POST")
	router.HandleFunc("/signup", SignUpHandler).Methods("POST")

	router.Use(JWTAuthentication)

	fmt.Println("Running API on http://localhost:8080")
	http.ListenAndServe(":8080", router)
	return nil
}

// HomeResponse is a response for HomeHandler
type HomeResponse struct {
	Project string `json:"project"`
	Version string `json:"version"`
}

// HomeHandler gives basic details about API
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	response := HomeResponse{
		Project: "go-ecommerce-api",
		Version: "v0",
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	json.NewEncoder(w).Encode(response)
}
