package com.bac.java_a2_005;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/users")
public class AdminUserExportController {

    private final JdbcTemplate jdbcTemplate;

    public AdminUserExportController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/export")
    public ResponseEntity<String> export() {
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "select id, username, email, phone, role from users");
        StringBuilder csv = new StringBuilder("id,username,email,phone,role\n");
        for (Map<String, Object> row : rows) {
            csv.append(row.get("id")).append(',')
                    .append(row.get("username")).append(',')
                    .append(row.get("email")).append(',')
                    .append(row.get("phone")).append(',')
                    .append(row.get("role")).append('\n');
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=users.csv")
                .body(csv.toString());
    }
}
