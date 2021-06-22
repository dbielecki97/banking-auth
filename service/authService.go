package service

import (
	"fmt"
	"github.com/dbielecki97/banking-auth/domain"
	"github.com/dbielecki97/banking-auth/dto"
	"github.com/dbielecki97/banking-lib/errs"
	"github.com/dbielecki97/banking-lib/logger"
	"github.com/dgrijalva/jwt-go"
)

type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Verify(params map[string]string) *errs.AppError
	Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError)
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
}

func NewDefaultAuthService(repo domain.AuthRepository, rolePermissions domain.RolePermissions) *DefaultAuthService {
	return &DefaultAuthService{repo: repo, rolePermissions: rolePermissions}
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) {
	var appErr *errs.AppError
	var login *domain.Login

	if login, appErr = s.repo.FindBy(req.Username, req.Password); appErr != nil {
		return nil, appErr
	}

	claims := login.ClaimsForAccessToken()
	authToken := domain.NewAuthToken(claims)

	var accessToken string
	if accessToken, appErr = authToken.NewAccessToken(); appErr != nil {
		return nil, appErr
	}

	var refreshToken string
	if refreshToken, appErr = s.repo.GenerateAndSaveRefreshTokenToStore(authToken); appErr != nil {
		return nil, appErr
	}

	return &dto.LoginResponse{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s DefaultAuthService) Verify(params map[string]string) *errs.AppError {
	if jwtToken, err := jwtTokenFromString(params["token"]); err != nil {
		return errs.NewAuthorization(err.Error())
	} else {
		if jwtToken.Valid {
			claims := jwtToken.Claims.(*domain.AccessTokenClaims)

			if claims.IsUserRole() {
				if !claims.IsRequestVerifiedWithTokenClaims(params) {
					return errs.NewAuthorization("request not verified with the token claims")
				}
			}

			isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, params["routeName"])
			if !isAuthorized {
				return errs.NewAuthorization(fmt.Sprintf("%s role is not authorized", claims.Role))
			}
			return nil
		} else {
			return errs.NewAuthorization("invalid token")
		}
	}
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMACSampleSecret), nil
	})
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}

func (s DefaultAuthService) Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError) {
	if vErr := request.IsAccessTokenValid(); vErr != nil {
		if vErr.Errors == jwt.ValidationErrorExpired {
			//continue with refresh token functionality

			var appErr *errs.AppError
			if appErr = s.repo.RefreshTokenExists(request.RefreshToken); appErr != nil {
				return nil, appErr
			}

			var accessToken string
			if accessToken, appErr = domain.NewAccessTokenFromRefreshToken(request.RefreshToken); appErr != nil {
				return nil, appErr
			}
			return &dto.LoginResponse{AccessToken: accessToken}, nil
		}
		return nil, errs.NewAuthentication("invalid token")
	}
	return nil, errs.NewAuthentication("cannot generate  a new access token until the current one expires")
}
