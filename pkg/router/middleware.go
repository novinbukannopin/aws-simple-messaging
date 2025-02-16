package router

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/kooroshh/fiber-boostrap/app/repository"
	"github.com/kooroshh/fiber-boostrap/pkg/jwt"
	"github.com/kooroshh/fiber-boostrap/pkg/response"
	"time"
)

func MiddlewareValidateAuth(ctx *fiber.Ctx) error {
	auth := ctx.Get("Authorization")
	if auth == "" {
		fmt.Println("Authorization header is missing")
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "Authorization header is missing", nil)
	}

	_, err := repository.GetUserSessionByToken(ctx.Context(), auth)
	if err != nil {
		fmt.Println("Error getting user session", err)
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "Error getting user session", nil)
	}

	claim, err := jwt.ValidateToken(ctx.Context(), auth)
	if err != nil {
		fmt.Println("Error validating token", err)
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "Error validating token", nil)
	}

	if time.Now().Unix() > claim.ExpiresAt.Unix() {
		fmt.Println("Token has expired")
		return response.SendFailureResponse(ctx, fiber.StatusUnauthorized, "Token has expired", nil)
	}

	ctx.Set("username", claim.Username)
	ctx.Set("full_name", claim.FullName)

	return ctx.Next()
}
