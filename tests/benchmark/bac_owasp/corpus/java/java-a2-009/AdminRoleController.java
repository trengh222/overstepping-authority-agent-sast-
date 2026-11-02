package com.bac.java_a2_009;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/users")
public class AdminRoleController {

    private final JdbcTemplate jdbcTemplate;

    public AdminRoleController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostMapping("/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> changeRole(@PathVariable("id") Long id,
                                          @RequestBody Map<String, String> payload) {
        jdbcTemplate.update("update users set role = ? where id = ?", payload.get("role"), id);
        return jdbcTemplate.queryForMap("select id, username, role from users where id = ?", id);
    }
}
