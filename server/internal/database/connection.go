package database

import (
	"database/sql"
	"fmt"
	"os"
	"sync"

	_ "modernc.org/sqlite"
)

var (
	DB   *sql.DB
	once sync.Once
)

func OpenInMemory() (*sql.DB, error) {
	var initErr error
	once.Do(func() {
		// Shared cache so multiple connections within the same process can see the same in-memory DB.
		databaseUrl, set := os.LookupEnv("DATABASE_URL")
		if !set {
			databaseUrl = "file:sessions.db?cache=shared"
		}
		fmt.Println(databaseUrl)
		conn, err := sql.Open("sqlite", databaseUrl)
		conn.SetMaxOpenConns(1)
		if err != nil {
			initErr = fmt.Errorf("open sqlite in-memory: %w", err)
			return
		}

		// Validate connectivity.
		if err := conn.Ping(); err != nil {
			_ = conn.Close()
			initErr = fmt.Errorf("ping sqlite: %w", err)
			return
		}
		DB = conn
	})

	if initErr != nil {
		return nil, initErr
	}
	if DB == nil {
		return nil, fmt.Errorf("sqlite db not initialized")
	}
	return DB, nil
}

// InitInMemory opens the DB and creates required tables.
func InitInMemory() (*sql.DB, error) {
	conn, err := OpenInMemory()
	if err != nil {
		return nil, err
	}
	if err := CreateTables(conn); err != nil {
		return nil, err
	}
	return conn, nil
}
