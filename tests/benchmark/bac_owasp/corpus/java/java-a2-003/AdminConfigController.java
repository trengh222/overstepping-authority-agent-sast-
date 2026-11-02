package com.bac.java_a2_003;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/config")
public class AdminConfigController {

    private final JdbcTemplate jdbcTemplate;

    public AdminConfigController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PutMapping
    public Map<String, Object> update(@RequestBody Map<String, String> payload) {
        payload.forEach((key, value) -> jdbcTemplate.update(
                "update system_config set config_value = ? where config_key = ?", value, key));
        return Map.<String, Object>of("updated", payload.size());
    }
}
