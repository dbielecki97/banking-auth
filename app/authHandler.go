package app

import (
	"encoding/json"
	"github.com/dbielecki97/banking-auth/dto"
	"github.com/dbielecki97/banking-auth/service"
	"github.com/dbielecki97/banking-lib/logger"
	"net/http"
)

type AuthHandler struct {
	service service.AuthService
}

func (h AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		logger.Error("Error while decoding login request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, err := h.service.Login(loginRequest)
		if err != nil {
			writeResponse(w, err.Code, err.AsMessage())
		} else {
			writeResponse(w, http.StatusOK, *token)
		}
	}
}

func (h AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	urlParams := make(map[string]string)

	for k := range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}

	if urlParams["token"] != "" {
		if err := h.service.Verify(urlParams); err != nil {
			writeResponse(w, http.StatusUnauthorized, notAuthorizedResponse(err.Error()))
		} else {
			writeResponse(w, http.StatusOK, authorizedResponse())
		}
	} else {
		writeResponse(w, http.StatusForbidden, notAuthorizedResponse("missing token"))
	}
}

func notAuthorizedResponse(msg string) map[string]interface{} {
	return map[string]interface{}{
		"is_authorized": false,
		"message":       msg,
	}
}

func authorizedResponse() map[string]bool {
	return map[string]bool{"is_authorized": true}
}

func writeResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}

func (h AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	panic("Not implemented")
}
