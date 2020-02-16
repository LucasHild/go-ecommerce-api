package api

func (s *Server) routes() {
	needsAuthenticationGroup := s.router.Group(nil)
	needsAuthenticationGroup.Use(s.JWTAuthentication)

	s.router.Get("/", s.HomeHandler)

	s.router.Get("/products", s.GetProductsHandler)
	needsAuthenticationGroup.Post("/products", s.AddProductHandler)
	s.router.Get("/products/{id}", s.GetProductHandler)
	needsAuthenticationGroup.Delete("/products/{id}", s.DeleteProductHandler)

	s.router.Post("/login", s.LoginHandler)
	s.router.Post("/signup", s.SignUpHandler)
	s.router.Get("/auth/google/login", s.AuthGoogleLogin)
	s.router.Get("/auth/google/redirect", s.AuthGoogleRedirect)
}
