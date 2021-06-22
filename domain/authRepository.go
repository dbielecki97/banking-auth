package domain

import "C"
import (
	"database/sql"
	"github.com/dbielecki97/banking-lib/errs"
	"github.com/dbielecki97/banking-lib/logger"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"strconv"
)

type AuthRepository interface {
	FindBy(username string, password string) (*Login, *errs.AppError)
	GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError)
	RefreshTokenExists(string) *errs.AppError
	SaveNewClient(Customer, User) (*string, *errs.AppError)
}

type AuthRepositoryDb struct {
	client *sqlx.DB
}

func NewAuthRepositoryDb(client *sqlx.DB) *AuthRepositoryDb {
	return &AuthRepositoryDb{client: client}
}

func (d AuthRepositoryDb) FindBy(username string, password string) (*Login, *errs.AppError) {
	var login Login
	sqlVerify := "SELECT username, customer_id, role, GROUP_CONCAT(a.account_id) as account_numbers from users u " +
		"LEFT JOIN accounts a using (customer_id) " +
		"where username = ? " +
		"and password = ? " +
		"group by customer_id;"

	err := d.client.Get(&login, sqlVerify, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewAuthentication("invalid credentials")
		} else {
			logger.Error("Error while verifying login request from database: " + err.Error())
			return nil, errs.NewUnexpected("unexpected database error")
		}
	}

	return &login, nil
}

func (d AuthRepositoryDb) GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError) {
	var appErr *errs.AppError
	var refreshToken string
	if refreshToken, appErr = authToken.newRefreshToken(); appErr != nil {
		return "", appErr
	}

	sqlInsert := "INSERT INTO refresh_token_store(refresh_token) values (?)"
	_, err := d.client.Exec(sqlInsert, refreshToken)
	if err != nil {
		logger.Error("unexpected database error" + err.Error())
		return "", errs.NewUnexpected("unexpected database error")
	}

	return refreshToken, nil
}

func (d AuthRepositoryDb) RefreshTokenExists(refreshToken string) *errs.AppError {
	sqlSelect := "select refresh_token from refresh_token_store where refresh_token = ?"
	var token string
	err := d.client.Get(&token, sqlSelect, refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return errs.NewAuthentication("refresh token not registered in the store")
		} else {
			logger.Error("Unexpected database error" + err.Error())
			return errs.NewUnexpected("unexpected database error")
		}

	}
	return nil
}

func (d AuthRepositoryDb) SaveNewClient(c Customer, u User) (*string, *errs.AppError) {
	tx, err := d.client.Begin()
	if err != nil {
		logger.Error("Could not start transaction" + err.Error())
		return nil, errs.NewUnexpected("unexpected database error")
	}

	sqlInsert := "insert into customers (name, date_of_birth, city, zipcode) values (?, ?, ?, ?)"
	result, err := tx.Exec(sqlInsert, c.Name, c.DateOfBirth, c.City, c.Zipcode)
	if err != nil {
		logger.Error("Unexpected database error while saving customer" + err.Error())
		return nil, errs.NewUnexpected("unexpected database error")
	}

	id, err := result.LastInsertId()
	if err != nil {
		tx.Rollback()
		logger.Error("Unexpected database error" + err.Error())
		return nil, errs.NewUnexpected("unexpected database error")
	}

	sqlInsert = "insert into users (username, password, role, customer_id) values (?, ?, ?, ?)"

	_, err = tx.Exec(sqlInsert, u.Username, u.Password, u.Role, id)
	if err != nil {
		tx.Rollback()
		logger.Error("Unexpected database error while saving user" + err.Error())
		return nil, errs.NewUnexpected("unexpected database error")
	}

	if err = tx.Commit(); err != nil {
		tx.Rollback()
		logger.Error("unexpected error while committing transaction")
		return nil, errs.NewUnexpected("unexpected database error")
	}
	stringId := strconv.FormatInt(id, 10)
	return &stringId, nil
}
