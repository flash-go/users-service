package entity

import (
	"time"
)

type Role struct {
	Id      string
	Name    string
	Created time.Time
}
