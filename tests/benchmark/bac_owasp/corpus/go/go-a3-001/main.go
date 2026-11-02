package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

type OrderRow struct {
	ID     int64 `json:"id"`
	UserID int64 `json:"user_id"`
	Amount int64 `json:"amount"`
}

func main() {
	db, _ := sql.Open("mysql", "dsn")
	r := gin.Default() // 全应用未注册任何认证中间件

	// 目标端点：内部订单导出，没有任何登录校验
	r.GET("/internal/export/orders", func(c *gin.Context) {
		rows, err := db.Query("SELECT id, user_id, amount FROM orders ORDER BY id")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "export failed"})
			return
		}
		defer rows.Close()

		out := []OrderRow{}
		for rows.Next() {
			var o OrderRow
			if err := rows.Scan(&o.ID, &o.UserID, &o.Amount); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
				return
			}
			out = append(out, o)
		}
		c.JSON(http.StatusOK, out)
	})

	r.Run(":8080")
}
