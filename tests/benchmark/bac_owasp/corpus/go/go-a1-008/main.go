package main

import (
	"database/sql"
	"net/http"

	"github.com/labstack/echo/v4"
)

type AssignTicket struct {
	AssigneeID int64 `json:"assignee_id"`
}

func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if c.Request().Header.Get("Authorization") == "" {
			return echo.ErrUnauthorized
		}
		c.Set("uid", int64(1001))
		return next(c)
	}
}

func main() {
	db, _ := sql.Open("mysql", "dsn")
	e := echo.New()
	e.Use(AuthMiddleware)

	// 工单转派：路径参数即工单主键，直接 UPDATE，未校验工单归属
	e.PUT("/api/tickets/:id/assign", func(c echo.Context) error {
		ticketID := c.Param("id")

		var in AssignTicket
		if err := c.Bind(&in); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
		}

		res, err := db.Exec("UPDATE tickets SET assignee_id = ? WHERE id = ?", in.AssigneeID, ticketID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "update failed"})
		}
		n, _ := res.RowsAffected()
		return c.JSON(http.StatusOK, map[string]any{"ticket": ticketID, "updated": n})
	})

	e.Logger.Fatal(e.Start(":8080"))
}
