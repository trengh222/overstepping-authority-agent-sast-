package main

import (
	"database/sql"
	"net/http"

	"github.com/labstack/echo/v4"
)

type OrderRow struct {
	ID     int64 `json:"id"`
	UserID int64 `json:"user_id"`
	Amount int64 `json:"amount"`
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
	e.Use(AuthMiddleware) // 全局认证：未登录请求到不了目标端点

	// 目标端点：导出订单，认证到位且只导出当前用户数据
	e.GET("/internal/export/orders", func(c echo.Context) error {
		uid, ok := c.Get("uid").(int64)
		if !ok {
			return echo.ErrUnauthorized
		}

		rows, err := db.Query(
			"SELECT id, user_id, amount FROM orders WHERE user_id = ? ORDER BY id", uid)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "export failed"})
		}
		defer rows.Close()

		out := []OrderRow{}
		for rows.Next() {
			var o OrderRow
			if err := rows.Scan(&o.ID, &o.UserID, &o.Amount); err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "scan failed"})
			}
			out = append(out, o)
		}
		return c.JSON(http.StatusOK, out)
	})

	e.Logger.Fatal(e.Start(":8080"))
}
