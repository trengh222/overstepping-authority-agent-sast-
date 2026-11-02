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

func main() {
	db, _ := sql.Open("mysql", "dsn")
	r := gin.Default()
	r.Use(AuthMiddleware())

	// 归属过滤：路径 id 与当前用户 uid 同时作为查询条件，命中他人订单时查不到
	r.GET("/api/orders/:id", func(c *gin.Context) {
		uid := c.GetInt64("uid")
		id := c.Param("id")

		var o Order
		err := db.QueryRow(
			"SELECT id, user_id, amount FROM orders WHERE id = ? AND user_id = ?", id, uid).
			Scan(&o.ID, &o.UserID, &o.Amount)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "order not found"})
			return
		}
		c.JSON(http.StatusOK, o)
	})

	r.Run(":8080")
}
