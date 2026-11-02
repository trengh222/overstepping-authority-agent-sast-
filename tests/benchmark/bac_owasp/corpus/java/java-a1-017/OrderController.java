package com.bac.java_a1_017;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final OrderMapper orderMapper;

    public OrderController(OrderMapper orderMapper) {
        this.orderMapper = orderMapper;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Object> detail(@PathVariable("id") Long id, HttpSession session) {
        Order order = orderMapper.selectById(id);
        if (order == null) {
            return ResponseEntity.notFound().build();
        }
        Long currentUserId = (Long) session.getAttribute("LOGIN_USER_ID");
        if (!order.getUserId().equals(currentUserId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "forbidden"));
        }
        return ResponseEntity.ok(order);
    }
}
