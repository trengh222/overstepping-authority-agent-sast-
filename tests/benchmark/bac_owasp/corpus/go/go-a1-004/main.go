package main

import (
	"database/sql"
	"net/http"

	"github.com/labstack/echo/v4"
)

type Document struct {
	ID      int64  `json:"id"`
	OwnerID int64  `json:"owner_id"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

// AuthMiddleware 把登录用户写入上下文；Echo 的中间件签名是 MiddlewareFunc。
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

	// 文档预览：doc_id 来自查询串，未校验 owner_id 是否等于当前用户
	e.GET("/api/documents/preview", func(c echo.Context) error {
		docID := c.QueryParam("doc_id")

		var d Document
		if err := db.QueryRow(
			"SELECT id, owner_id, title, content FROM documents WHERE id = ?", docID).
			Scan(&d.ID, &d.OwnerID, &d.Title, &d.Content); err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "document not found"})
		}
		return c.JSON(http.StatusOK, d)
	})

	e.Logger.Fatal(e.Start(":8080"))
}
