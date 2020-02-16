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
func (s *Server) GetProductsHandler(w http.ResponseWriter, r *http.Request) {
	products := []Product{}
	err := mgm.Coll(&Product{}).SimpleFind(&products, bson.M{})
	if err != nil {
		log.Fatalln(err)
	}

	rnd.JSON(w, http.StatusOK, map[string]interface{}{
		"products": products,
	})
}

// AddProductHandler creates a new product
func (s *Server) AddProductHandler(w http.ResponseWriter, r *http.Request) {
	var product Product

	err := json.NewDecoder(r.Body).Decode(&product)
	if err != nil {
		RespondWithMessage(w, http.StatusBadRequest, "Invalid JSON Payload")
		return
	}

	err = product.validate()
	if err != nil {
		RespondWithMessage(w, http.StatusBadRequest, err.Error())
		return
	}

	product.CreatedBy = r.Context().Value(contextKeyUserID).(string)

	err = mgm.Coll(&product).Create(&product)
	if err != nil {
		log.Fatalln("Error saving product to DB", err)
		RespondWithMessage(w, http.StatusInternalServerError, "An error occurred")
	}

	rnd.JSON(w, http.StatusOK, map[string]interface{}{
		"product": product,
	})
}

// GetProductResponse is a response for GetProductHandler
type GetProductResponse struct {
	Product Product `json:"product"`
}

// GetProductHandler returns product by id
func (s *Server) GetProductHandler(w http.ResponseWriter, r *http.Request) {
	productID := chi.URLParam(r, "id")

	var product Product
	err := mgm.Coll(&product).FindByID(productID, &product)
	if err != nil {
		RespondWithMessage(w, http.StatusNotFound, "A product with this ID doesn't exist")
		return
	}

	rnd.JSON(w, http.StatusOK, map[string]interface{}{
		"product": product,
	})
}

// DeleteProductHandler deletes a product
func (s *Server) DeleteProductHandler(w http.ResponseWriter, r *http.Request) {
	productID := chi.URLParam(r, "id")

	product := Product{}
	err := mgm.Coll(&product).FindByID(productID, &product)
	if err != nil {
		RespondWithMessage(w, http.StatusNotFound, "A product with this ID doesn't exist")
		return
	}

	if product.CreatedBy != r.Context().Value(contextKeyUserID).(string) {
		RespondWithMessage(w, http.StatusForbidden, "Only the author of the product can delete it")
		return
	}

	err = mgm.Coll(&product).Delete(&product)
	if err != nil {
		RespondWithMessage(w, http.StatusInternalServerError, "An error occurred")
		return
	}

	RespondWithMessage(w, http.StatusOK, "Deleted product successfully")
}
