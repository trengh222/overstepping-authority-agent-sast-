package main

import (
	"bytes"
	"database/sql"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func main() {
	db, _ := sql.Open("mysql", "dsn")
	_ = db
	r := gin.Default() // 未注册认证中间件

	// 目标端点：内部数据库备份，匿名即可触发
	r.POST("/internal/admin/backup", func(c *gin.Context) {
		var out bytes.Buffer
		cmd := exec.Command("sh", "-c", "mysqldump --single-transaction app > /srv/backup/app.sql")
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "backup failed", "log": out.String()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	r.Run(":8080")
}
