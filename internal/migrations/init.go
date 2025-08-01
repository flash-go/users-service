package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func Migration_users_init() *gormigrate.Migration {
	return &gormigrate.Migration{
		ID: "users_init",
		Migrate: func(tx *gorm.DB) error {
			if err := tx.Exec(`
				CREATE TABLE IF NOT EXISTS user_roles (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL UNIQUE,
					created TIMESTAMPTZ NOT NULL
				);
			`).Error; err != nil {
				return err
			}

			if err := tx.Exec(`
				CREATE TABLE IF NOT EXISTS users (
					id SERIAL PRIMARY KEY,
					created TIMESTAMPTZ NOT NULL,
					username TEXT NOT NULL UNIQUE,
					email TEXT NOT NULL UNIQUE,
					password TEXT NOT NULL,
					role_id TEXT NOT NULL,
					mfa BOOLEAN DEFAULT FALSE,
					otp_secret TEXT NOT NULL,
					CONSTRAINT fk_role FOREIGN KEY (role_id)
						REFERENCES user_roles(id)
						ON UPDATE CASCADE
						ON DELETE RESTRICT
				);
			`).Error; err != nil {
				return err
			}

			if err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);`).Error; err != nil {
				return err
			}

			return nil
		},

		Rollback: func(tx *gorm.DB) error {
			if err := tx.Exec(`DROP TABLE IF EXISTS users;`).Error; err != nil {
				return err
			}
			if err := tx.Exec(`DROP TABLE IF EXISTS user_roles;`).Error; err != nil {
				return err
			}
			return nil
		},
	}
}
