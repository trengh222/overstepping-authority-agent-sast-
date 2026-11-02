package com.bac.java_b6_005;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api/me/orders")
public class MyOrderSummaryController {

    private final JdbcTemplate jdbcTemplate;

    public MyOrderSummaryController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/{id}")
    public OrderVO summary(@PathVariable("id") Long id, HttpSession session) {
        Long userId = (Long) session.getAttribute("LOGIN_USER_ID");
        return jdbcTemplate.queryForObject(
                "select id, order_no, status, total_amount from orders where id = ? and user_id = ?",
                (rs, rowNum) -> new OrderVO(
                        rs.getLong("id"),
                        rs.getString("order_no"),
                        rs.getString("status"),
                        rs.getBigDecimal("total_amount").toPlainString()),
                id, userId);
    }
}
