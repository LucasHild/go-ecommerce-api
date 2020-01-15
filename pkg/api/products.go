package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/Kamva/mgm"
	"github.com/globalsign/mgo/bson"
	"github.com/go-chi/chi"
)

// GetProductsResponse is a response for GetProductsHandler
type GetProductsResponse struct {
	Products []Product `json:"products"`
}

// GetProductsHandler returns all products
func GetProductsHandler(w http.ResponseWriter, r *http.Request) {
	products := []Product{}
	err := mgm.Coll(&Product{}).SimpleFind(&products, bson.M{})
	if err != nil {
		log.Fatalln(err)
	}

	response := GetProductsResponse{Products: products}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Fatalln("Error marshalling data", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// AddProductResponse is a response for AddProductHandler
type AddProductResponse struct {
	Product Product `json:"product"`
}

// AddProductHandler creates a new product
func AddProductHandler(w http.ResponseWriter, r *http.Request) {
	var product Product

	err := json.NewDecoder(r.Body).Decode(&product)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		RespondWithMessage(w, "Invalid JSON Payload")
		return
	}

	err = product.validate()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		RespondWithMessage(w, err.Error())
		return
	}

	product.CreatedBy = r.Context().Value(contextKeyUserID).(string)

	err = mgm.Coll(&product).Create(&product)
	if err != nil {
		log.Fatalln("Error saving product to DB", err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	response := AddProductResponse{Product: product}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Fatalln("Error marshalling data", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// GetProductResponse is a response for GetProductHandler
type GetProductResponse struct {
	Product Product `json:"product"`
}

// GetProductHandler returns product by id
func GetProductHandler(w http.ResponseWriter, r *http.Request) {
	productID := chi.URLParam(r, "id")

	product := Product{}
	err := mgm.Coll(&product).FindByID(productID, &product)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		RespondWithMessage(w, "A product with this ID doesn't exist")
		return
	}

	response := GetProductResponse{Product: product}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Fatalln("Error marshalling data", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// DeleteProductHandler deletes a product
func DeleteProductHandler(w http.ResponseWriter, r *http.Request) {
	productID := chi.URLParam(r, "id")

	product := Product{}
	err := mgm.Coll(&product).FindByID(productID, &product)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		RespondWithMessage(w, "A product with this ID doesn't exist")
		return
	}

	if product.CreatedBy != r.Context().Value(contextKeyUserID).(string) {
		w.WriteHeader(http.StatusForbidden)
		RespondWithMessage(w, "Only the author of the product can delete it")
		return
	}

	err = mgm.Coll(&product).Delete(&product)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		RespondWithMessage(w, "An error occurred")
		return
	}

	RespondWithMessage(w, "Deleted product successfully")
}
