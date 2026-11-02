package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Message struct {
	ID       int64  `json:"id"`
	SenderID int64  `json:"sender_id"`
	Body     string `json:"body"`
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

	// 收件箱列表：归属用户取自 c.Query("user_id")，没有和上下文里的 uid 比对
	r.GET("/api/messages", func(c *gin.Context) {
		boxOwner := c.Query("user_id")

		rows, err := db.Query(
			"SELECT id, sender_id, body FROM messages WHERE receiver_id = ? ORDER BY id DESC", boxOwner)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		defer rows.Close()

		msgs := []Message{}
		for rows.Next() {
			var m Message
			if err := rows.Scan(&m.ID, &m.SenderID, &m.Body); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "scan error"})
				return
			}
			msgs = append(msgs, m)
		}
		c.JSON(http.StatusOK, msgs)
	})

	r.Run(":8080")
}
