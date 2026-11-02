package com.bac.java_a3_004;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/ops/health")
public class OpsHealthController {

    private final JdbcTemplate jdbcTemplate;

    public OpsHealthController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/detail")
    public Map<String, Object> detail() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("dbUrl", jdbcTemplate.queryForObject("select current_setting('data_directory')", String.class));
        result.put("dbUser", jdbcTemplate.queryForObject("select current_user", String.class));
        result.put("openConnections",
                jdbcTemplate.queryForObject("select count(*) from pg_stat_activity", Integer.class));
        result.put("pendingTasks",
                jdbcTemplate.queryForObject("select count(*) from job_runs where status = 'RUNNING'", Integer.class));
        return result;
    }
}
