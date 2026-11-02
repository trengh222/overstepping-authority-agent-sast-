package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware 校验登录态并把当前用户写入上下文 uid。
// 真实项目里会解 JWT / 查 session，这里简化成固定用户。
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if len(auth) < 8 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
			return
		}
		c.Set("uid", int64(1001))
		c.Next()
	}
}
