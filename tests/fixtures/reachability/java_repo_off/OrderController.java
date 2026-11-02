package com.example.shop;

import com.example.shop.entity.Order;
import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/** IDOR 正样本 + 仓库配置声明 orders.export.enabled=false → 配置不可达（降级工单）。 */
@RestController
@RequestMapping("/api")
public class OrderController {

    @Autowired
    private OrderService orderService;

    // [A1] 仓库配置键 orders.export.enabled 声明为 false
    @GetMapping("/orders/{oid}")
    public Order exportOrders(@PathVariable("oid") Long oid) {
        if (!flags.isEnabled("orders.export.enabled")) {
            throw new IllegalStateException("export disabled");
        }
        return orderService.findById(oid);
    }
}
