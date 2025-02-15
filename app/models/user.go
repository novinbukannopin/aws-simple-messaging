package models

import (
	"github.com/go-playground/validator/v10"
	"time"
)

type User struct {
	ID        uint   `gorm:"primarykey"`
	Username  string `json:"username" gorm:"unique;type:varchar(20)" validate:"required,min=6,max=32"`
	FullName  string `json:"full_name" gorm:"type:varchar(200);" validate:"required,min=6"`
	Password  string `json:"password" gorm:"type:varchar(255);" validate:"required,min=6"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (l User) Validate() error {
	v := validator.New()
	return v.Struct(l)
}

type UserSession struct {
	ID                  uint      `gorm:"primarykey"`
	UserId              uint      `json:"user_id" gorm:"type:int" validate:"required"`
	Token               string    `json:"token" gorm:"type:varchar(255)" validate:"required"`
	RefreshToken        string    `json:"refresh_token" gorm:"type:varchar(255)" validate:"required"`
	TokenExpired        time.Time `json:"-" validate:"required"`
	RefreshTokenExpired time.Time `json:"-" validate:"required"`
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func (l UserSession) Validate() error {
	v := validator.New()
	return v.Struct(l)
}
