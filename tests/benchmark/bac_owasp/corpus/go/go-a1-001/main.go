package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Order struct {
	ID     int64  `json:"id"`
	UserID int64  `json:"user_id"`
	Amount int64  `json:"amount"`
	Status string `json:"status"`
}

// AuthMiddleware 解析 Authorization 头并注入当前用户（演示用简化实现）。
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

	// 订单详情：c.Param("id") 直接进 WHERE，未附加当前用户归属条件
	r.GET("/api/orders/:id", func(c *gin.Context) {
		id := c.Param("id")

		var o Order
		err := db.QueryRow("SELECT id, user_id, amount, status FROM orders WHERE id = ?", id).
			Scan(&o.ID, &o.UserID, &o.Amount, &o.Status)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "order not found"})
			return
		}
		c.JSON(http.StatusOK, o)
	})

	r.Run(":8080")
}
