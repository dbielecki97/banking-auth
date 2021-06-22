package app

import (
	"fmt"
	"github.com/dbielecki97/banking-auth/domain"
	"github.com/dbielecki97/banking-auth/service"
	"github.com/dbielecki97/banking-lib/logger"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"net/http"
	"os"
	"time"
)

func Start() {
	sanityCheck()
	router := mux.NewRouter()

	authRepository := domain.NewAuthRepositoryDb(getDbClient())

	ah := AuthHandler{service.NewDefaultAuthService(authRepository, domain.GetRolePermissions())}

	router.HandleFunc("/auth/login", ah.Login).Methods(http.MethodPost)
	router.HandleFunc("/auth/register", ah.Register).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", ah.Verify).Methods(http.MethodGet)
	router.HandleFunc("/auth/refresh", ah.Refresh).Methods(http.MethodPost)

	address := os.Getenv("SERVER_ADDRESS")
	port := os.Getenv("SERVER_PORT")

	logger.Info(fmt.Sprintf("Starting OAuth server on %s:%s...", address, port))
	err := http.ListenAndServe(fmt.Sprintf("%s:%s", address, port), router)
	if err != nil {
		logger.Fatal(err.Error())
	}
}

func sanityCheck() {
	keys := []string{
		"SERVER_ADDRESS",
		"SERVER_PORT",
		"DB_USER",
		"DB_PASSWD",
		"DB_ADDR",
		"DB_PORT",
		"DB_NAME"}

	allPresent := true
	for _, e := range keys {
		ok := checkEnvVariable(e)
		if allPresent != false {
			allPresent = ok
		}
	}

	if !allPresent {
		os.Exit(1)
	}
}

func checkEnvVariable(key string) bool {
	if os.Getenv(key) == "" {
		logger.Error("Environment variable " + key + " not defined!")
		return false
	}
	return true
}

func getDbClient() *sqlx.DB {
	dbUser := os.Getenv("DB_USER")
	dbPasswd := os.Getenv("DB_PASSWD")
	dbAddr := os.Getenv("DB_ADDR")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	dataSource := "%s:%s@tcp(%s:%s)/%s"
	client, err := sqlx.Open("mysql", fmt.Sprintf(dataSource, dbUser, dbPasswd, dbAddr, dbPort, dbName))
	if err != nil {
		panic(err)
	}

	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxIdleConns(10)
	client.SetMaxOpenConns(10)
	return client
}
