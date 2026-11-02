package main

import (
	"database/sql"
)

// OrderDTO 是对外投影，只含展示需要的字段。
type OrderDTO struct {
	ID     int64 `json:"id"`
	Amount int64 `json:"amount"`
}

type OrderRepo struct {
	db *sql.DB
}

func NewOrderRepo() *OrderRepo {
	db, _ := sql.Open("mysql", "dsn")
	return &OrderRepo{db: db}
}

// GetByIDAndUser 以 (order id, user id) 为联合条件，确保只返回调用者自己的订单。
func (r *OrderRepo) GetByIDAndUser(id string, uid int64) (*OrderDTO, error) {
	var dto OrderDTO
	err := r.db.QueryRow(
		"SELECT id, amount FROM orders WHERE id = ? AND user_id = ?", id, uid).
		Scan(&dto.ID, &dto.Amount)
	if err != nil {
		return nil, err
	}
	return &dto, nil
}
