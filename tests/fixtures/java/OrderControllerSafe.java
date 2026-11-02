package com.example.shop;

import com.example.shop.entity.Order;
import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

/** 负样本：查询中带当前用户归属约束（findByUserIdAndId），不应报越权。 */
@RestController
@RequestMapping("/api/order")
public class OrderControllerSafe {

    @Autowired
    private OrderService orderService;

    @GetMapping("/{id}")
    public Order getOrder(@PathVariable("id") Long id, Principal principal) {
        return orderService.findByUserIdAndId(principal.getName(), id);
    }

    @GetMapping("/mine/{id}")
    @PreAuthorize("isAuthenticated()")
    public Order getMine(@PathVariable("id") Long id, Principal principal) {
        return orderService.findByUserIdAndId(principal.getName(), id);
    }
}