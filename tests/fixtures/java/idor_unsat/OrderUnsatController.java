package com.example.shop;

import com.example.shop.entity.Order;
import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/** 符号执行负样本-不可达：sink 仅在 id<0 分支，与合法主键域矛盾 → 求不出反例。 */
@RestController
@RequestMapping("/api/order")
public class OrderUnsatController {

    @Autowired
    private OrderService orderService;

    @GetMapping("/{id}")
    public Order getOrder(@PathVariable("id") Long id) {
        if (id < 0) {
            return orderService.findById(id);
        }
        return null;
    }
}