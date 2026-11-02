package com.bac.java_a1_016;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class OrderExportService {

    private final JdbcTemplate jdbcTemplate;

    public OrderExportService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> exportSelected(List<Long> orderIds) {
        String placeholders = String.join(",", orderIds.stream().map(id -> "?").toList());
        String sql = "select id, user_id, amount, status from orders where id in (" + placeholders + ")";
        return jdbcTemplate.queryForList(sql, orderIds.toArray());
    }
}
