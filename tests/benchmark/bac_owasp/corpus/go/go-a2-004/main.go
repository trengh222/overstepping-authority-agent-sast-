package main

import (
	"database/sql"
	"net/http"

	"github.com/labstack/echo/v4"
)

// AuthMiddleware 认证：注入 uid / role。
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

// RequireAdmin 授权：非 admin 角色一律 403。
func RequireAdmin() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if role, _ := c.Get("role").(string); role != "admin" {
				return echo.NewHTTPError(http.StatusForbidden, "admin only")
			}
			return next(c)
		}
	}
}

func main() {
	db, _ := sql.Open("mysql", "dsn")
	e := echo.New()

	// 管理员组：认证 + 角色两道中间件都挂在组上
	admin := e.Group("/admin", AuthMiddleware, RequireAdmin)

	// 目标端点：删除用户，进入 handler 前已保证是 admin
	admin.DELETE("/users/:id", func(c echo.Context) error {
		id := c.Param("id")

		if _, err := db.Exec("DELETE FROM users WHERE id = ?", id); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "delete failed"})
		}
		return c.JSON(http.StatusOK, map[string]string{"deleted": id})
	})

	e.Logger.Fatal(e.Start(":8080"))
}
