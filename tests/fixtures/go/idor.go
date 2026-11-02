package main

import (
	"database/sql"
	"github.com/gin-gonic/gin"
)

func main() {
	db, _ := sql.Open("mysql", "dsn")
	r := gin.Default()

	// [A1] Path 参数流入 SQL 直查，无 user_id 约束
	r.GET("/api/order/:id", func(c *gin.Context) {
		id := c.Param("id")
		var name string
		db.QueryRow("SELECT name FROM t_order WHERE id = ?", id).Scan(&name)
	})
}