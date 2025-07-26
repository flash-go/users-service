package model

import "time"

type UserRole struct {
	Id      string    `gorm:"primarykey"`
	Name    string    `gorm:"uniqueIndex;not null"`
	Created time.Time `gorm:"not null"`
}
