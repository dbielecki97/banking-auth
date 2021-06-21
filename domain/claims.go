package domain

import "github.com/dgrijalva/jwt-go"

type AccessTokenClaims struct {
	CustomerId string   `json:"customer_id"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"username"`
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
