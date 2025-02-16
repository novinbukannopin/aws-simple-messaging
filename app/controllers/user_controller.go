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
	user := new(models.LoginRequest)
	resp := models.LoginResponse{}

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

	token, err := jwt.GenerateToken(ctx.Context(), data.Username, data.FullName, "token")
	if err != nil {
		errResponse := fmt.Errorf("error generating token", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	refreshToken, err := jwt.GenerateToken(ctx.Context(), data.Username, data.FullName, "refresh_token")
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
