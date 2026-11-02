package main

import (
	"database/sql"
	"net/http"

	"github.com/labstack/echo/v4"
)

// Account 是实体，序列化时把卡号与令牌一并带出。
type Account struct {
	ID          int64  `json:"id"`
	OwnerID     int64  `json:"owner_id"`
	Balance     int64  `json:"balance"`
	CardNo      string `json:"card_no"`
	AccessToken string `json:"access_token"`
}

func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if c.Request().Header.Get("Authorization") == "" {
			return echo.ErrUnauthorized
		}
		c.Set("uid", int64(1001))
		return next(c)
	}
}

func main() {
	db, _ := sql.Open("mysql", "dsn")
	e := echo.New()
	e.Use(AuthMiddleware)

	// 当前用户的账户信息：查询条件已绑定 uid，但返回体是完整实体
	e.GET("/api/billing/accounts/current", func(c echo.Context) error {
		uid, ok := c.Get("uid").(int64)
		if !ok {
			return echo.ErrUnauthorized
		}

		var a Account
		if err := db.QueryRow(
			"SELECT id, owner_id, balance, card_no, access_token FROM accounts WHERE owner_id = ?", uid).
			Scan(&a.ID, &a.OwnerID, &a.Balance, &a.CardNo, &a.AccessToken); err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "account not found"})
		}
		return c.JSON(http.StatusOK, a)
	})

	e.Logger.Fatal(e.Start(":8080"))
}
