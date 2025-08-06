package model

import "time"

type User struct {
	Id        uint      `gorm:"primarykey"`
	Created   time.Time `gorm:"not null"`
	Username  string    `gorm:"uniqueIndex;not null"`
	Email     string    `gorm:"uniqueIndex;not null"`
	Password  string    `gorm:"not null"`
	Name      string    `gorm:"not null"`
	RoleId    string    `gorm:"not null"`
	Role      UserRole  `gorm:"foreignKey:RoleId;references:Id;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Mfa       bool      `gorm:"default:false;"`
	OtpSecret string    `gorm:"not null"`
}
