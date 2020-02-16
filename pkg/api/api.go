package api

import (
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/gorilla/sessions"
	"github.com/unrolled/render"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Server keeps track of router, config and more
type Server struct {
	router          chi.Router
	config          Config
	cookieStore     *sessions.CookieStore
	googleOauthConf *oauth2.Config
}

var rnd *render.Render

// Start the server on port 8080
func (s *Server) Start() {
	s.init()

	log.Println("Running API on http://localhost:8080")
	err := http.ListenAndServe(":8080", s.router)
	if err != nil {
		log.Println("Unable to start server:", err)
	}
}

// Start the API server
func (s *Server) init() {
	s.config = getConfig()

	s.router = chi.NewRouter()
	s.routes()

	connectToDB(s.config)

	rnd = render.New(render.Options{})

	s.cookieStore = sessions.NewCookieStore(s.config.sessionKey)
	s.googleOauthConf = &oauth2.Config{
		ClientID:     s.config.googleOauthClientID,
		ClientSecret: s.config.googleOauthClientSecret,
		RedirectURL:  "http://127.0.0.1:8080/auth/google/redirect",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
}

// HomeHandler gives basic details about API
func (s *Server) HomeHandler(w http.ResponseWriter, r *http.Request) {
	rnd.JSON(w, http.StatusOK, map[string]string{
		"project": "go-ecommerce-api",
		"version": "v0",
	})
}
