package main

// A1 负例：SQL 带 user_id，取认证中间件写入的 uid。
import (
    "database/sql"
    "net/http"

    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.GET("/api/documents/:id", func(c *gin.Context) {
        uid, _ := c.Get("uid")
        db, _ := sql.Open("sqlite3", "app.db")
        var row map[string]any
        db.QueryRow(
            "SELECT * FROM documents WHERE id = ? AND user_id = ?", c.Param("id"), uid,
        ).Scan(&row)
        c.JSON(http.StatusOK, row)
    })
    r.Run(":8080")
}
