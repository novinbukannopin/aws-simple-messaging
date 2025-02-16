package controllers

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/kooroshh/fiber-boostrap/app/models"
	"github.com/kooroshh/fiber-boostrap/app/repository"
	"github.com/kooroshh/fiber-boostrap/pkg/jwt"
	"github.com/kooroshh/fiber-boostrap/pkg/response"
	"golang.org/x/crypto/bcrypt"
	"time"
)

func Register(ctx *fiber.Ctx) error {
	user := new(models.User)

	err := ctx.BodyParser(user)
	if err != nil {
		errResponse := fmt.Errorf("error parsing user", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	err = user.Validate()
	if err != nil {
		errResponse := fmt.Errorf("error validating user", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		errResponse := fmt.Errorf("error hashing password", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	user.Password = string(hashPassword)

	err = repository.InsertNewUser(ctx.Context(), user)
	if err != nil {
		errResponse := fmt.Errorf("error inserting user", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	resp := user
	resp.Password = ""

	return response.SendSuccessResponse(ctx, resp)
}

func Login(ctx *fiber.Ctx) error {
	var (
		user = new(models.LoginRequest)
		resp = models.LoginResponse{}
		now  = time.Now()
	)

	if err := ctx.BodyParser(user); err != nil {
		errResponse := fmt.Errorf("error parsing user", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	err := user.Validate()
	if err != nil {
		errResponse := fmt.Errorf("error validating user", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	data, err := repository.GetUserByUsername(ctx.Context(), user.Username)
	if err != nil {
		errResponse := fmt.Errorf("error getting user", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusNotFound, errResponse.Error(), nil)
	}

	err = bcrypt.CompareHashAndPassword([]byte(data.Password), []byte(user.Password))
	if err != nil {
		errResponse := fmt.Errorf("error comparing password", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, errResponse.Error(), nil)
	}

	token, err := jwt.GenerateToken(ctx.Context(), data.Username, data.FullName, "token", now)
	if err != nil {
		errResponse := fmt.Errorf("error generating token", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	refreshToken, err := jwt.GenerateToken(ctx.Context(), data.Username, data.FullName, "refresh_token", now)
	if err != nil {
		errResponse := fmt.Errorf("error generating refresh token", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	err = repository.InsertNewUserSession(ctx.Context(), &models.UserSession{
		UserId:              data.ID,
		Token:               token,
		RefreshToken:        refreshToken,
		TokenExpired:        time.Now().Add(jwt.MapTypeToken["token"]),
		RefreshTokenExpired: time.Now().Add(jwt.MapTypeToken["refresh_token"]),
	})

	resp.Username = data.Username
	resp.FullName = data.FullName
	resp.Token = token
	resp.RefreshToken = refreshToken

	return response.SendSuccessResponse(ctx, resp)
}

func Logout(ctx *fiber.Ctx) error {
	token := ctx.Get("Authorization")
	err := repository.DeleteUserSessionByToken(ctx.Context(), token)
	if err != nil {
		errResponse := fmt.Errorf("error deleting user session", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}
	return response.SendSuccessResponse(ctx, nil)
}

func RefreshToken(ctx *fiber.Ctx) error {
	now := time.Now()
	username := ctx.Locals("username").(string)
	fullName := ctx.Locals("full_name").(string)
	refreshToken := ctx.Get("Authorization")

	token, err := jwt.GenerateToken(ctx.Context(), username, fullName, "token", now)
	if err != nil {
		errResponse := fmt.Errorf("error generating token", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	err = repository.UpdateUserSessionByToken(ctx.Context(), token, now.Add(jwt.MapTypeToken["token"]), refreshToken)
	if err != nil {
		errResponse := fmt.Errorf("error updating user session", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	return response.SendSuccessResponse(ctx, fiber.Map{
		"token": token,
	})
}
