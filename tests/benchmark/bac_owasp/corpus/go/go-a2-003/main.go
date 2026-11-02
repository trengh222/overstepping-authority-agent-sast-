package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

type BalanceAdjust struct {
	Delta int64 `json:"delta"`
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

	// /admin/** 组只挂认证中间件，组内没有任何角色/管理员守卫
	admin := r.Group("/admin", AuthMiddleware())

	// 目标端点：调整账户余额，资金类特权操作
	admin.POST("/accounts/:id/balance", func(c *gin.Context) {
		accountID := c.Param("id")

		var in BalanceAdjust
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}

		_, err := db.Exec("UPDATE accounts SET balance = balance + ? WHERE id = ?", in.Delta, accountID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "adjust failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"account": accountID, "delta": in.Delta})
	})

	r.Run(":8080")
}
