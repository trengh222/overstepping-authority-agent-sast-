package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

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
	repo := NewOrderRepo()
	r := gin.Default()
	r.Use(AuthMiddleware())

	// 订单详情：仓储层按 (id, uid) 联合取数，再以 DTO 输出，越权与字段泄露均被规避
	r.GET("/api/orders/:id", func(c *gin.Context) {
		uid := c.GetInt64("uid")
		id := c.Param("id")

		dto, err := repo.GetByIDAndUser(id, uid)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "order not found"})
			return
		}
		c.JSON(http.StatusOK, dto)
	})

	r.Run(":8080")
}
