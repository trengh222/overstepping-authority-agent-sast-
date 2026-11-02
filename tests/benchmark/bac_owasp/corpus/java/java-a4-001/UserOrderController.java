package com.bac.java_a4_001;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/orders")
public class UserOrderController {

    private final JdbcTemplate jdbcTemplate;

    public UserOrderController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/mine")
    public List<Map<String, Object>> mine(@RequestHeader("X-User-Id") Long userId) {
        return jdbcTemplate.queryForList(
                "select id, order_no, total_amount, status from orders where user_id = ?", userId);
    }
}
