package database

import (
	"database/sql"
	"errors"
	"fmt"
)

// CreateTables creates all database tables used by the server.
func CreateTables(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("create tables: db is nil")
	}
	// session: stores client session material derived during key exchange.
	// ephemeral_aes_key is stored as raw bytes (BLOB).
	const createSession = `
		CREATE TABLE IF NOT EXISTS session (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			client_id TEXT,
			salt TEXT NOT NULL,
			ephemeral_aes_key BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`

	if _, err := db.Exec(createSession); err != nil {
		return fmt.Errorf("create session table: %w", err)
	}
	return nil
}

// CreateSession stores session material for a client.
func CreateSession(db *sql.DB, clientID *int, salt string, ephemeralAESKey []byte) (int, error) {
	if db == nil {
		return 0, fmt.Errorf("insert session: db is nil")
	}
	const q = `
		INSERT INTO session (client_id, salt, ephemeral_aes_key)
		VALUES (?, ?, ?)
	`
	result, err := db.Exec(q, clientID, salt, ephemeralAESKey)
	if err != nil {
		return 0, fmt.Errorf("insert session: %w", err)
	}
	insertedId, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("can't get the inserted row id %w", err)
	}
	return int(insertedId), nil
}

// GetSession returns salt and ephemeral AES key for a client.
func GetSession(db *sql.DB, sessionId int) (salt string, ephemeralAESKey []byte, ok bool, err error) {
	if db == nil {
		return "", nil, false, fmt.Errorf("get session: db is nil")
	}
	const q = `SELECT salt, ephemeral_aes_key FROM session WHERE id = ?`

	row := db.QueryRow(q, sessionId)
	var key []byte
	if scanErr := row.Scan(&salt, &key); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return "", nil, false, nil
		}
		return "", nil, false, fmt.Errorf("get session: %w", scanErr)
	}
	return salt, key, true, nil
}
