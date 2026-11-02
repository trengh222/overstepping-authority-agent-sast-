package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Invoice struct {
	ID       int64   `json:"id"`
	TenantID int64   `json:"tenant_id"`
	Total    float64 `json:"total"`
	PDFURL   string  `json:"pdf_url"`
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
	r := gin.New()
	r.Use(AuthMiddleware())

	// 发票详情：路径里的发票号直接作为主键查询，租户归属未参与条件
	r.GET("/api/invoices/:invoiceId", func(c *gin.Context) {
		invID := c.Param("invoiceId")

		const q = "SELECT id, tenant_id, total, pdf_url FROM invoices WHERE id = ?"
		var inv Invoice
		if err := db.QueryRow(q, invID).Scan(&inv.ID, &inv.TenantID, &inv.Total, &inv.PDFURL); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"msg": "query failed"})
			return
		}
		c.JSON(http.StatusOK, inv)
	})

	r.Run(":8080")
}
