package com.bac.java_a3_006;

import java.util.Map;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/users")
public class InternalPasswordController {

    private final JdbcTemplate jdbcTemplate;

    public InternalPasswordController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostMapping("/{id}/reset-password")
    public Map<String, Object> reset(@PathVariable("id") Long id) {
        String temporaryPassword = UUID.randomUUID().toString().substring(0, 12);
        jdbcTemplate.update("update users set password = ? where id = ?", temporaryPassword, id);
        return Map.<String, Object>of("userId", id, "password", temporaryPassword);
    }
}
