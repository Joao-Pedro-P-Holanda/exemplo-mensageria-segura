package database

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

var (
	DB   *gorm.DB
	once sync.Once
)

func OpenInMemory() (*gorm.DB, error) {
	var initErr error
	once.Do(func() {
		// Shared cache so multiple connections within the same process can see the same in-memory DB.
		databaseUrl, set := os.LookupEnv("DATABASE_URL")
		if !set {
			databaseUrl = "file:sessions.db?cache=shared"
		}
		slog.Info("Database connection", "url", databaseUrl)

		conn, err := gorm.Open(sqlite.Open(databaseUrl), &gorm.Config{})
		if err != nil {
			initErr = fmt.Errorf("open sqlite: %w", err)
			return
		}

		sqlDB, err := conn.DB()
		if err != nil {
			initErr = fmt.Errorf("get sql db: %w", err)
			return
		}

		sqlDB.SetMaxOpenConns(1)
		// SetMaxIdleConns and SetConnMaxLifetime are good practices,
		// but MaxOpenConns=1 is critical for sqlite generic concurrent access if not WAL.
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetConnMaxLifetime(time.Hour)

		// Validate connectivity.
		if err := sqlDB.Ping(); err != nil {
			_ = sqlDB.Close()
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
func InitInMemory() (*gorm.DB, error) {
	conn, err := OpenInMemory()
	if err != nil {
		return nil, err
	}
	if err := AutoMigrate(conn); err != nil {
		return nil, err
	}
	return conn, nil
}
