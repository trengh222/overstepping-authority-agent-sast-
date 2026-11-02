package main

import (
	"database/sql"
	"net/http"

	"github.com/labstack/echo/v4"
)

type RoleChange struct {
	Role string `json:"role"`
}

// AuthMiddleware 仅做认证：注入 uid，并把角色固定成普通用户。
func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if c.Request().Header.Get("Authorization") == "" {
			return echo.ErrUnauthorized
		}
		c.Set("uid", int64(1001))
		c.Set("role", "user")
		return next(c)
	}
}

func main() {
	db, _ := sql.Open("mysql", "dsn")
	e := echo.New()
	e.Use(AuthMiddleware) // 全应用认证：任何已登录用户都能到达 /admin/**

	// 目标端点：修改任意用户的角色（含自提权），没有 admin 角色校验
	e.PUT("/admin/users/:id/role", func(c echo.Context) error {
		userID := c.Param("id")

		var in RoleChange
		if err := c.Bind(&in); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
		}
		if in.Role == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "role required")
		}

		if _, err := db.Exec("UPDATE users SET role = ? WHERE id = ?", in.Role, userID); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "update failed"})
		}
		return c.JSON(http.StatusOK, map[string]string{"user": userID, "role": in.Role})
	})

	e.Logger.Fatal(e.Start(":8080"))
}
