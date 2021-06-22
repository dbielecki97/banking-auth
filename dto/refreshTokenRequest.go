package dto

import (
	"errors"
	"github.com/dbielecki97/banking-auth/domain"
	"github.com/dgrijalva/jwt-go"
)

type RefreshTokenRequest struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (r RefreshTokenRequest) IsAccessTokenValid() *jwt.ValidationError {
	_, err := jwt.Parse(r.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMACSampleSecret), nil
	})
	if err != nil {
		var vErr *jwt.ValidationError
		if errors.As(err, &vErr) {
			return vErr
		}
	}

	return nil
}
