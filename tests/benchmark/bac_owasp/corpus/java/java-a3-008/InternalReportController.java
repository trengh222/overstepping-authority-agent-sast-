package com.bac.java_a3_008;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/reports")
public class InternalReportController {

    private final JdbcTemplate jdbcTemplate;

    public InternalReportController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/{date}")
    @PreAuthorize("isAuthenticated()")
    public Map<String, Object> daily(@PathVariable("date") String date) {
        return jdbcTemplate.queryForMap(
                "select date, order_count, gross_amount from daily_reports where date = ?", date);
    }
}
