package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
)

func client() *http.Client {
	config := &tls.Config{InsecureSkipVerify: true}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: config}}
}

func find(db *sql.DB, name string) {
	query := fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", name)
	_, err := db.Query(query)
	if err != nil {
	}
}

func retry() {
	panic("not implemented")
}

func main() {
	client()
	retry()
}
