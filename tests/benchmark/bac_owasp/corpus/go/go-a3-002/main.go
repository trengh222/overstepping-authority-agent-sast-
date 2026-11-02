package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ProfileDTO struct {
	UserID   int64  `json:"user_id"`
	Nickname string `json:"nickname"`
	JoinedAt string `json:"joined_at"`
}

func main() {
	db, _ := sql.Open("mysql", "dsn")
	r := gin.Default() // 没有 r.Use(...)，也没有路由级认证

	// 目标端点：用户资料，匿名请求可直接按 id 取任意用户资料
	r.GET("/api/users/:id/profile", func(c *gin.Context) {
		userID := c.Param("id")

		var p ProfileDTO
		err := db.QueryRow(
			"SELECT id, nickname, created_at FROM users WHERE id = ?", userID).
			Scan(&p.UserID, &p.Nickname, &p.JoinedAt)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusOK, p)
	})

	r.Run(":8080")
}
