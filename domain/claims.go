package domain

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

const (
	AccessTokenDuration  = time.Hour
	RefreshTokenDuration = time.Hour * 24 * 30
)

type AccessTokenClaims struct {
	CustomerId string   `json:"customer_id"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	jwt.StandardClaims
}

type RefreshTokenClaims struct {
	TokenType  string   `json:"token_type"`
	CustomerId string   `json:"cid"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"un"`
	Role       string   `json:"role"`
	jwt.StandardClaims
}

func (c AccessTokenClaims) IsUserRole() bool {
	if c.Role == "user" {
		return true
	}

	return false
}

func (c AccessTokenClaims) IsRequestVerifiedWithTokenClaims(params map[string]string) bool {
	if c.CustomerId != params["customer_id"] {
		return false
	}

	if !c.IsValidAccountId(params["account_id"]) {
		return false
	}

	return true
}

func (c AccessTokenClaims) IsValidAccountId(accId string) bool {
	if accId != "" {
		accountFound := false
		for _, a := range c.Accounts {
			if a == accId {
				accountFound = true
				break
			}
		}
		return accountFound
	}
	return true
}

func (c AccessTokenClaims) RefreshTokenClaims() RefreshTokenClaims {
	return RefreshTokenClaims{
		TokenType:      "refresh_token",
		CustomerId:     c.CustomerId,
		Accounts:       c.Accounts,
		Username:       c.Username,
		Role:           c.Role,
		StandardClaims: jwt.StandardClaims{ExpiresAt: time.Now().Add(RefreshTokenDuration).Unix()},
	}
}

func (c RefreshTokenClaims) AccessTokenClaims() AccessTokenClaims {
	return AccessTokenClaims{
		CustomerId:     c.CustomerId,
		Accounts:       c.Accounts,
		Username:       c.Username,
		Role:           c.Role,
		StandardClaims: jwt.StandardClaims{ExpiresAt: time.Now().Add(AccessTokenDuration).Unix()},
	}
}
