package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	db, _ := sql.Open("mysql", "dsn")
	r := gin.Default()

	// /admin/** 组只挂了认证中间件（证明是已登录用户），没有组级角色守卫
	admin := r.Group("/admin", AuthMiddleware())

	// 同组的另一条路由自己加了 RequireRole("admin")
	admin.GET("/users", RequireRole("admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"items": []gin.H{}})
	})

	// 目标端点：删除用户，只有认证、没有角色校验
	admin.DELETE("/users/:id", func(c *gin.Context) {
		id := c.Param("id")

		if _, err := db.Exec("DELETE FROM users WHERE id = ?", id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"deleted": id})
	})

	r.Run(":8080")
}
