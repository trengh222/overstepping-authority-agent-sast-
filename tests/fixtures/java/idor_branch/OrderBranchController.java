package com.example.shop;

import com.example.shop.entity.Order;
import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/** 符号执行正样本：sink 仅在 id>1000 分支可达（带路径约束，法尔例应 >1000）。 */
@RestController
@RequestMapping("/api/order")
public class OrderBranchController {

    @Autowired
    private OrderService orderService;

    @GetMapping("/{id}")
    public Order getOrder(@PathVariable("id") Long id) {
        if (id == null || id <= 0) {
            return null;
        }
        if (id > 1000) {
            return orderService.findById(id);
        }
        return null;
    }
}