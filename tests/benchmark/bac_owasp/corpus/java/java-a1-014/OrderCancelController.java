package com.bac.java_a1_014;

import java.util.Map;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/orders")
public class OrderCancelController {

    private final OrderCancelMapper orderCancelMapper;

    public OrderCancelController(OrderCancelMapper orderCancelMapper) {
        this.orderCancelMapper = orderCancelMapper;
    }

    @PostMapping("/{id}/cancel")
    public Map<String, Object> cancel(@PathVariable("id") Long id) {
        orderCancelMapper.cancelById(id);
        return orderCancelMapper.selectById(id);
    }
}
