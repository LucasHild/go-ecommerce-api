package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
)

// Start the API server
func Start() error {
	fmt.Println("Connecting to db ...")
	connectToDB()
	config.load()

	router := chi.NewRouter()
	needsAuthenticationGroup := router.Group(nil)
	needsAuthenticationGroup.Use(JWTAuthentication)

	router.Get("/", HomeHandler)

	router.Get("/products", GetProductsHandler)
	needsAuthenticationGroup.Post("/products", AddProductHandler)
	router.Get("/products/{id}", GetProductHandler)
	needsAuthenticationGroup.Delete("/products/{id}", DeleteProductHandler)

	router.Post("/login", LoginHandler)
	router.Post("/signup", SignUpHandler)

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
