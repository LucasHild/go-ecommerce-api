package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

func Start() error {
	connectToDB()

	router := mux.NewRouter()
	router.HandleFunc("/", HomeHandler)
	router.HandleFunc("/products", GetProducts).Methods("GET")
	router.HandleFunc("/products", AddProduct).Methods("POST")
	http.ListenAndServe(":8080", router)
	return nil
}

type IndexResponse struct {
	Project string `json:"project"`
	Version string `json:"version"`
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	response := IndexResponse{
		Project: "go-ecommerce-api",
		Version: "v0",
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	json.NewEncoder(w).Encode(response)
}
