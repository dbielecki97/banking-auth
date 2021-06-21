package service

import (
	"errors"
	"fmt"
	"github.com/dbielecki97/banking-auth/domain"
	"github.com/dbielecki97/banking-auth/dto"
	"github.com/dgrijalva/jwt-go"
	"log"
)

type AuthService interface {
	Login(dto.LoginRequest) (*string, error)
	Verify(params map[string]string) error
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
}

func NewDefaultAuthService(repo domain.AuthRepository, rolePermissions domain.RolePermissions) *DefaultAuthService {
	return &DefaultAuthService{repo: repo, rolePermissions: rolePermissions}
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*string, error) {
	login, err := s.repo.FindBy(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	token, err := login.GenerateToken()
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (s DefaultAuthService) Verify(params map[string]string) error {
	if jwtToken, err := jwtTokenFromString(params["token"]); err != nil {
		return errors.New("not authorized")
	} else {
		if jwtToken.Valid {
			claims := jwtToken.Claims.(*domain.AccessTokenClaims)

			if claims.IsUserRole() {
				if !claims.IsRequestVerifiedWithTokenClaims(params) {
					return errors.New("request not verified with the token claims")
				}
			}

			isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, params["routeName"])
			if !isAuthorized {
				return errors.New(fmt.Sprintf("%s role is not authorized", claims.Role))
			}
			return nil
		} else {
			return errors.New("invalid token")
		}
	}
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMACSampleSecret), nil
	})
	if err != nil {
		log.Println("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}
