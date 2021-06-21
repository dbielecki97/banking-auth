package domain

import (
	"database/sql"
	"github.com/dbielecki97/banking-lib/errs"
	"github.com/dbielecki97/banking-lib/logger"
	"github.com/dgrijalva/jwt-go"
	"strings"
	"time"
)

const (
	TokenDuration    = time.Hour
	HMACSampleSecret = "samplesecret"
)

type Login struct {
	Username   string         `db:"username"`
	CustomerId sql.NullString `db:"customer_id"`
	Accounts   sql.NullString `db:"account_numbers"`
	Role       string         `db:"role"`
}

func (l Login) GenerateToken() (*string, *errs.AppError) {
	var claims jwt.MapClaims
	if l.Accounts.Valid && l.CustomerId.Valid {
		claims = l.claimsForUser()
	} else {
		claims = l.claimsForAdmin()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signetTokenAsString, err := token.SignedString([]byte(HMACSampleSecret))
	if err != nil {
		logger.Error("Failed while signing token: " + err.Error())
		return nil, errs.NewUnexpected("cannot generate token")
	}
	return &signetTokenAsString, nil
}

func (l Login) claimsForUser() jwt.MapClaims {
	accounts := strings.Split(l.Accounts.String, ",")
	return jwt.MapClaims{
		"customer_id": l.CustomerId.String,
		"role":        l.Role,
		"username":    l.Username,
		"accounts":    accounts,
		"exp":         time.Now().Add(TokenDuration).Unix(),
	}
}

func (l Login) claimsForAdmin() jwt.MapClaims {
	return jwt.MapClaims{
		"role":     l.Role,
		"username": l.Username,
		"exp":      time.Now().Add(TokenDuration).Unix(),
	}
}
