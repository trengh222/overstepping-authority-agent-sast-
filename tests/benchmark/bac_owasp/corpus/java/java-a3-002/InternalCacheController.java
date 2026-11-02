package com.bac.java_a3_002;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/cache")
public class InternalCacheController {

    private final JdbcTemplate jdbcTemplate;

    public InternalCacheController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/dump")
    public List<Map<String, Object>> dump() {
        return jdbcTemplate.queryForList(
                "select cache_key, cache_value, owner_id, expired_at from cache_entries");
    }
}
