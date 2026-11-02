package com.bac.java_a4_003;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/reports")
public class PersonalReportController {

    private final JdbcTemplate jdbcTemplate;

    public PersonalReportController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/personal")
    public Map<String, Object> personal(@CookieValue(value = "uid", defaultValue = "0") Long uid) {
        Map<String, Object> result = new LinkedHashMap<>();
        List<Map<String, Object>> records = jdbcTemplate.queryForList(
                "select id, title, amount, created_at from personal_reports where user_id = ?", uid);
        result.put("uid", uid);
        result.put("records", records);
        return result;
    }
}
