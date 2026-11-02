package main

// A1：Gin 路径参数直接查库返回，无归属校验。
import (
    "database/sql"
    "net/http"

    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.GET("/api/files/:id", func(c *gin.Context) {
        var row map[string]any
        db, _ := sql.Open("sqlite3", "app.db")
        db.QueryRow("SELECT * FROM files WHERE id = ?", c.Param("id")).Scan(&row)
        c.JSON(http.StatusOK, row)
    })
    r.Run(":8080")
}
