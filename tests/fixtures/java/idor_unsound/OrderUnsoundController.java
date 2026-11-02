package com.example.shop;

import com.example.shop.entity.Order;
import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/** 符号执行负样本-unsound：条件为未解释方法调用 → 不产出反例（保持 LIKELY）。 */
@RestController
@RequestMapping("/api/order")
public class OrderUnsoundController {

    @Autowired
    private OrderService orderService;

    @GetMapping("/{id}")
    public Order getOrder(@PathVariable("id") Long id) {
        if (orderService.exists(id)) {
            return orderService.findById(id);
        }
        return null;
    }
}