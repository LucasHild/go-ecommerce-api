package api

import (
	"log"
	"net/http"
)

func (s *Server) routes() {
	needsAuthenticationGroup := s.router.Group(nil)
	needsAuthenticationGroup.Use(s.JWTAuthentication)

	s.router.Get("/", handler(s.HomeHandler))

	s.router.Get("/products", s.GetProductsHandler)
	needsAuthenticationGroup.Post("/products", s.AddProductHandler)
	s.router.Get("/products/{id}", s.GetProductHandler)
	needsAuthenticationGroup.Delete("/products/{id}", s.DeleteProductHandler)

	s.router.Post("/login", handler(s.LoginHandler))
	s.router.Post("/signup", handler(s.SignUpHandler))
	s.router.Get("/auth/google/login", s.AuthGoogleLogin)
	s.router.Get("/auth/google/redirect", s.AuthGoogleRedirect)
}

type handlerFunc func(w http.ResponseWriter, r *http.Request) error

func handler(h handlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := h(w, r)
		if err != nil {
			if serr, ok := err.(UserError); ok {
				rnd.JSON(w, serr.StatusCode, serr)
			} else {
				log.Println(err)
				serr := UserError{Cause: err, StatusCode: 500, Message: "An unknown error occurred"}
				rnd.JSON(w, serr.StatusCode, serr)
			}
		}
	})
}
