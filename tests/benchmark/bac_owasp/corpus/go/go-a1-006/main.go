package main

import (
	"database/sql"
	"net/http"

	"github.com/labstack/echo/v4"
)

type FileMeta struct {
	ID         int64  `json:"id"`
	UploaderID int64  `json:"uploader_id"`
	StorageKey string `json:"storage_key"`
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

	// 附件下载：显式比较 uploader_id 与当前用户，非本人直接 403
	e.GET("/api/files/:id/download", func(c echo.Context) error {
		uid, ok := c.Get("uid").(int64)
		if !ok {
			return echo.ErrUnauthorized
		}
		id := c.Param("id")

		var f FileMeta
		if err := db.QueryRow(
			"SELECT id, uploader_id, storage_key FROM files WHERE id = ?", id).
			Scan(&f.ID, &f.UploaderID, &f.StorageKey); err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "file not found"})
		}
		if f.UploaderID != uid {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
		}

		return c.File("/data/uploads/" + f.StorageKey)
	})

	e.Logger.Fatal(e.Start(":8080"))
}
