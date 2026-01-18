package database

import (
	"time"

	"gorm.io/gorm"
)

// Session stores client session material derived during key exchange.
type Session struct {
	ID              uint   `gorm:"primaryKey"`
	ClientID        string `gorm:"index"`
	Salt            string `gorm:"not null"`
	EphemeralAESKey []byte `gorm:"not null"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       gorm.DeletedAt `gorm:"index"`
}

// AutoMigrate migrates the schema.
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(&Session{})
}
