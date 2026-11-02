package main

import (
	"database/sql"
	"net/http"

	"github.com/labstack/echo/v4"
)

type Message struct {
	ID       int64  `json:"id"`
	ThreadID int64  `json:"thread_id"`
	SenderID int64  `json:"sender_id"`
	Body     string `json:"body"`
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

	// 会话历史：threadId 取自路径，未确认当前用户是否属于该会话
	e.GET("/api/messages/thread/:threadId", func(c echo.Context) error {
		threadID := c.Param("threadId")

		rows, err := db.Query(
			"SELECT id, thread_id, sender_id, body FROM messages WHERE thread_id = ?", threadID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "db error"})
		}
		defer rows.Close()

		list := []Message{}
		for rows.Next() {
			var m Message
			if err := rows.Scan(&m.ID, &m.ThreadID, &m.SenderID, &m.Body); err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "scan error"})
			}
			list = append(list, m)
		}
		return c.JSON(http.StatusOK, list)
	})

	e.Logger.Fatal(e.Start(":8080"))
}
