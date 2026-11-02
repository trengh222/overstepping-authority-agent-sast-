package com.bac.gen.orders_pos;

/** 无所有权过滤：按主键直接取。 */
public class OrderService {

    public Order getById(Long id) {
        return OrderMapper.selectById(id);
    }
}
