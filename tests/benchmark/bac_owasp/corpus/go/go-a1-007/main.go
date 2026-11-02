package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Order struct {
	ID     int64 `json:"id"`
	UserID int64 `json:"user_id"`
	Amount int64 `json:"amount"`
}

type BatchQuery struct {
	IDs []int64 `json:"ids"`
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

	// 批量订单查询：ids 全部来自请求体，按主键逐条取数，未限制归属
	r.POST("/api/orders/batch", func(c *gin.Context) {
		var in BatchQuery
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}

		out := make([]Order, 0, len(in.IDs))
		for _, id := range in.IDs {
			var o Order
			err := db.QueryRow("SELECT id, user_id, amount FROM orders WHERE id = ?", id).
				Scan(&o.ID, &o.UserID, &o.Amount)
			if err != nil {
				continue
			}
			out = append(out, o)
		}
		c.JSON(http.StatusOK, gin.H{"items": out})
	})

	r.Run(":8080")
}
