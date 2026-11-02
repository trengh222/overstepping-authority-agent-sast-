package com.example.shop;

import com.example.shop.entity.Order;
import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/** 数据事实样本：资源标识为 UUID（不可枚举假设）→ 只降级，不关闭。 */
@RestController
@RequestMapping("/api/order")
public class OrderUuidController {

    @Autowired
    private OrderService orderService;

    @GetMapping("/{id}")
    public Order getOrder(@PathVariable("id") UUID id) {
        return orderService.findById(id);
    }
}
