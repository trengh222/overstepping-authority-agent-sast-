package com.bac.java_a2_007;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/backup")
public class AdminBackupController {

    private final JdbcTemplate jdbcTemplate;

    public AdminBackupController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostMapping("/run")
    public Map<String, Object> run(@RequestParam(value = "target", defaultValue = "full") String target) {
        jdbcTemplate.update(
                "insert into backup_jobs (target, status, created_at) values (?, 'RUNNING', now())",
                target);
        Long jobId = jdbcTemplate.queryForObject("select max(id) from backup_jobs", Long.class);
        return Map.<String, Object>of("jobId", jobId, "target", target, "status", "RUNNING");
    }
}
