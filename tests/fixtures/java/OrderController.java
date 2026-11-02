package com.example.shop;

import com.example.shop.entity.Order;
import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/** 正样本：两个水平越权点（无归属约束的 ID 直查）。 */
@RestController
@RequestMapping("/api/order")
public class OrderController {

    @Autowired
    private OrderService orderService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // [A1] JPA findById 无归属校验
    @GetMapping("/{id}")
    public Order getOrder(@PathVariable("id") Long id) {
        return orderService.findById(id);
    }

    // [A1] 原生 SQL 按 id 直查，无 user_id 约束
    @GetMapping("/raw/{id}")
    public Map<String, Object> getOrderRaw(@PathVariable("id") Long id) {
        return jdbcTemplate.queryForMap(
                "SELECT * FROM t_order WHERE id = ?", id);
    }
}