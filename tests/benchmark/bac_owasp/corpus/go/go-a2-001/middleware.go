package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware 只负责“是谁”：校验登录态并注入 uid / role。
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
			return
		}
		c.Set("uid", int64(1001))
		c.Set("role", "user")
		c.Next()
	}
}

// RequireRole 负责“能不能”：比较上下文里的角色。
func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("role") != role {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}
