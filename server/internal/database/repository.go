package database

import (
	"context"

	"gorm.io/gorm"
)

// AutoMigrate migrates the schema.
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(&Session{})
}

// Create ensures the type T is saved to the database.
func Create[T any](ctx context.Context, entity *T) error {
	return gorm.G[T](DB).Create(ctx, entity)
}

// FindByID finds a record of type T by its ID.
func FindByID[T any](ctx context.Context, id uint) (*T, error) {
	return gorm.G[*T](DB).Where("id = ?", id).First(ctx)
}
