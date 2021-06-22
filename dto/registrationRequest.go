package dto

import (
	"database/sql"
	"github.com/dbielecki97/banking-auth/domain"
	"github.com/dbielecki97/banking-lib/errs"
)

type RegistrationRequest struct {
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	Name        string `json:"name,omitempty"`
	City        string `json:"city,omitempty"`
	Zipcode     string `json:"zipcode,omitempty"`
	DateOfBirth string `json:"date_of_birth,omitempty"`
}

func (r RegistrationRequest) CreateUser() domain.User {
	return domain.User{
		Username:   r.Username,
		Password:   r.Password,
		Role:       "user",
		CustomerId: sql.NullString{},
	}
}

func (r RegistrationRequest) CreateCustomer() domain.Customer {
	return domain.Customer{
		Name:        r.Name,
		City:        r.City,
		Zipcode:     r.Zipcode,
		DateOfBirth: r.DateOfBirth,
		Status:      "1",
	}
}

func (r RegistrationRequest) Validate() *errs.AppError {
	if r.Username == "" || r.Password == "" || r.Name == "" || r.City == "" || r.Zipcode == "" || r.DateOfBirth == "" {
		return errs.NewValidation("all fields must be provided")
	}
	return nil
}
