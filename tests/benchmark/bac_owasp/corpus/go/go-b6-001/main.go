package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

// User 是持久化实体，字段直接带对外 JSON tag。
type User struct {
	ID       int64  `json:"id"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
	Password string `json:"password"`
	CardNo   string `json:"card_no"`
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
			return
		}
		c.Set("uid", int64(1001))
		c.Next()
	}
}

func main() {
	db, _ := sql.Open("mysql", "dsn")
	r := gin.Default()
	r.Use(AuthMiddleware())

	// 本人资料：归属没问题（uid 来自上下文），但把实体结构体整体序列化，
	// password / card_no 等敏感字段原样出现在响应里
	r.GET("/api/users/me", func(c *gin.Context) {
		uid := c.GetInt64("uid")

		var u User
		err := db.QueryRow(
			"SELECT id, nickname, email, password, card_no FROM users WHERE id = ?", uid).
			Scan(&u.ID, &u.Nickname, &u.Email, &u.Password, &u.CardNo)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusOK, u)
	})

	r.Run(":8080")
}
