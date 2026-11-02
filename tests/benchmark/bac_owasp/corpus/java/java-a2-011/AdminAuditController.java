package com.bac.java_a2_011;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.security.RolesAllowed;

@RestController
@RequestMapping("/api/admin/audit")
public class AdminAuditController {

    private final JdbcTemplate jdbcTemplate;

    public AdminAuditController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping
    @RolesAllowed("ADMIN")
    public List<Map<String, Object>> query(@RequestParam(value = "actor", required = false) String actor) {
        return jdbcTemplate.queryForList(
                "select id, actor, action, target, created_at from audit_log where actor like ?",
                "%" + actor + "%");
    }
}
