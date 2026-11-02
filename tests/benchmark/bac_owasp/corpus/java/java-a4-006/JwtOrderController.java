package com.bac.java_a4_006;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Claims;

@RestController
@RequestMapping("/api/orders")
public class JwtOrderController {

    private final JdbcTemplate jdbcTemplate;
    private final JwtService jwtService;

    public JwtOrderController(JdbcTemplate jdbcTemplate, JwtService jwtService) {
        this.jdbcTemplate = jdbcTemplate;
        this.jwtService = jwtService;
    }

    @GetMapping("/mine")
    public ResponseEntity<Object> mine(@RequestHeader(value = "Authorization", required = false) String authorization) {
        String token = authorization != null && authorization.startsWith("Bearer ")
                ? authorization.substring(7)
                : null;
        Claims claims = token == null ? null : jwtService.parse(token);
        if (claims == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid token"));
        }
        Long userId = claims.get("uid", Long.class);
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "select id, order_no, total_amount, status from orders where user_id = ?", userId);
        return ResponseEntity.ok(rows);
    }
}
