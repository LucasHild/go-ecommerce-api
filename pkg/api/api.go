package api

import (
	"fmt"
	"net/http"

	"github.com/unrolled/render"

	"github.com/go-chi/chi"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var rnd *render.Render
var cookieStore *sessions.CookieStore
var googleOauthConf *oauth2.Config

// Start the API server
func Start() error {
	fmt.Println("Connecting to db ...")
	config.load()
	connectToDB()

	cookieStore = sessions.NewCookieStore(config.sessionKey)
	googleOauthConf = &oauth2.Config{
		ClientID:     config.googleOauthClientID,
		ClientSecret: config.googleOauthClientSecret,
		RedirectURL:  "http://127.0.0.1:8080/auth/google/redirect",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}

	rnd = render.New(render.Options{})

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
	router.Get("/auth/google/login", AuthGoogleLogin)
	router.Get("/auth/google/redirect", AuthGoogleRedirect)

	fmt.Println("Running API on http://localhost:8080")
	http.ListenAndServe(":8080", router)
	return nil
}

// HomeHandler gives basic details about API
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	rnd.JSON(w, http.StatusOK, map[string]string{
		"project": "go-ecommerce-api",
		"version": "v0",
	})
}
