package api

import "fmt"

// UserError is used to indicate user what went wrong
type UserError struct {
	StatusCode int    `json:"-"`
	Message    string `json:"message"`
	Cause      error  `json:"-"`
}

func (e UserError) Error() string {
	return fmt.Sprintf("UserError %v: %v (%v)", e.StatusCode, e.Message, e.Cause.Error())
}
