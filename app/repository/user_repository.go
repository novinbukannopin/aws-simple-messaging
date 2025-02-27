package repository

import (
	"context"
	"github.com/kooroshh/fiber-boostrap/app/models"
	"github.com/kooroshh/fiber-boostrap/pkg/database"
	"time"
)

func InsertNewUser(ctx context.Context, user *models.User) error {
	return database.DB.Create(user).Error
}

func GetUserByUsername(ctx context.Context, username string) (models.User, error) {
	var (
		user models.User
		err  error
	)
	err = database.DB.Where("username = ?", username).First(&user).Error
	return user, err
}

func InsertNewUserSession(ctx context.Context, userSession *models.UserSession) error {
	return database.DB.Create(userSession).Error
}

func GetUserSessionByToken(ctx context.Context, token string) (models.UserSession, error) {
	var (
		userSession models.UserSession
		err         error
	)
	err = database.DB.Where("token = ?", token).Last(&userSession).Error
	return userSession, err
}

func DeleteUserSessionByToken(ctx context.Context, token string) error {
	return database.DB.Exec("DELETE FROM user_sessions WHERE token = ?", token).Error
}

func UpdateUserSessionByToken(ctx context.Context, token string, tokenExpired time.Time, refreshToken string) error {
	return database.DB.Exec("UPDATE user_sessions SET token = ?, token_expired = ? WHERE refresh_token = ?", token, tokenExpired, refreshToken).Error
}
