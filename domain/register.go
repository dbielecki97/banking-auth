package domain

import "database/sql"

type Customer struct {
	Id          string `db:"customer_id"`
	Name        string
	City        string
	Zipcode     string
	DateOfBirth string `db:"date_of_birth"`
	Status      string
}

type User struct {
	Username   string         `json:"username,omitempty"`
	Password   string         `json:"password,omitempty"`
	Role       string         `json:"role,omitempty"`
	CustomerId sql.NullString `json:"customer_id"`
	CreatedOn  string         `json:"created_on,omitempty"`
}
