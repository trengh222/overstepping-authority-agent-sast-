package com.bac.gen.orders_neg;

/** 归属过滤：id + userId 双条件。 */
public class OrderService {

    public Order getByIdAndUserId(Long id, Long userId) {
        return OrderMapper.selectByIdAndUserId(id, userId);
    }
}
