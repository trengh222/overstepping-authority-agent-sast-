package com.bac.java_a2_001;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {

    private final JdbcTemplate jdbcTemplate;

    public AdminUserController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public List<Map<String, Object>> list() {
        return jdbcTemplate.queryForList("select id, username, role from users");
    }

    @PostMapping("/{id}/role")
    public Map<String, Object> changeRole(@PathVariable("id") Long id,
                                          @RequestBody RoleRequest request) {
        jdbcTemplate.update("update users set role = ? where id = ?", request.getRole(), id);
        return jdbcTemplate.queryForMap("select id, username, role from users where id = ?", id);
    }

    public static class RoleRequest {

        private String role;

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }
    }
}
