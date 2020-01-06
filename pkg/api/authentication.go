package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// JWTAuthentication is a middleware that checks authentication
// https://medium.com/@adigunhammedolalekan/build-and-deploy-a-secure-rest-api-with-go-postgresql-jwt-and-gorm-6fadf3da505b
func JWTAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHeader := r.Header.Get("Authorization")

		if tokenHeader == "" {
			w.WriteHeader(http.StatusForbidden)
			RespondWithMessage(w, "Missing auth token")
			return
		}

		splitted := strings.Split(tokenHeader, " ")
		if len(splitted) != 2 {
			w.WriteHeader(http.StatusForbidden)
			RespondWithMessage(w, "Invalid auth token")
			return
		}

		token := splitted[1]
		fmt.Println("Token", token)

		ctx := context.WithValue(r.Context(), "user", "EXAMPLE_USER_ID")
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
		return
	})
}
