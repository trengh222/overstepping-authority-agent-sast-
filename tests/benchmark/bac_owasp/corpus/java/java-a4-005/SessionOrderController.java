package com.bac.java_a4_005;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api/orders")
public class SessionOrderController {

    private final JdbcTemplate jdbcTemplate;

    public SessionOrderController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/mine")
    public ResponseEntity<Object> mine(HttpSession session) {
        Object sessionUserId = session.getAttribute("LOGIN_USER_ID");
        if (sessionUserId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "login required"));
        }
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "select id, order_no, total_amount, status from orders where user_id = ?", sessionUserId);
        return ResponseEntity.ok(rows);
    }
}
