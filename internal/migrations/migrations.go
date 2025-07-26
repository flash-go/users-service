package migrations

import "github.com/go-gormigrate/gormigrate/v2"

func Get() []*gormigrate.Migration {
	return []*gormigrate.Migration{
		Migration_users_init(),
	}
}
