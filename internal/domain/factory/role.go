package factory

import (
	"time"

	"github.com/flash-go/users-service/internal/domain/entity"
)

func NewRole(data RoleData) *entity.Role {
	return &entity.Role{
		Id:      data.Id,
		Name:    data.Name,
		Created: time.Unix(0, data.Created.UnixNano()),
	}
}

type RoleData struct {
	Id      string
	Name    string
	Created time.Time
}
