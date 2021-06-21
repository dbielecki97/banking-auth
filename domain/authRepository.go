package domain

import (
	"database/sql"
	"errors"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"log"
)

type AuthRepository interface {
	FindBy(username string, password string) (*Login, error)
}

type AuthRepositoryDb struct {
	client *sqlx.DB
}

func NewAuthRepositoryDb(client *sqlx.DB) *AuthRepositoryDb {
	return &AuthRepositoryDb{client: client}
}

func (d AuthRepositoryDb) FindBy(username string, password string) (*Login, error) {
	var login Login
	sqlVerify := "SELECT username, customer_id, role, GROUP_CONCAT(a.account_id) as account_numbers from users u " +
		"LEFT JOIN accounts a using (customer_id) " +
		"where username = ? " +
		"and password = ? " +
		"group by customer_id;"

	err := d.client.Get(&login, sqlVerify, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("invalid credentials")
		} else {
			log.Println("Error while verifying login request from database: " + err.Error())
			return nil, errors.New("unexpected database error")
		}
	}

	return &login, nil
}
