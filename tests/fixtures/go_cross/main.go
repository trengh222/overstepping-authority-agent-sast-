package main

import (
	"database/sql"
	"github.com/gin-gonic/gin"
)

// 正样本：仅按 id 查询，无归属约束（跨过程进入 FindByID 方法体）
func FindByID(db *sql.DB, id string) (string, error) {
	var name string
	err := db.QueryRow("SELECT name FROM orders WHERE id = ?", id).Scan(&name)
	return name, err
}

// 负样本：带 user_id 归属约束
func FindOwnOrder(db *sql.DB, id string, userID string) (string, error) {
	var name string
	err := db.QueryRow("SELECT name FROM orders WHERE id = ? AND user_id = ?", id, userID).Scan(&name)
	return name, err
}

func main() {
	var db *sql.DB
	r := gin.Default()
	r.GET("/api/order/:id", func(c *gin.Context) {
		id := c.Param("id")
		FindByID(db, id)
	})
	r.GET("/api/order/mine/:id", func(c *gin.Context) {
		id := c.Param("id")
		FindOwnOrder(db, id, "current-user")
	})
}
