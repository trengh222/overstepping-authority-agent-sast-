package com.bac.java_a3_003;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/jobs")
public class InternalJobController {

    private final JdbcTemplate jdbcTemplate;

    public InternalJobController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostMapping("/run")
    public Map<String, Object> run(@RequestParam("jobName") String jobName) {
        jdbcTemplate.update(
                "insert into job_runs (job_name, status, started_at) values (?, 'RUNNING', now())",
                jobName);
        return Map.<String, Object>of("job", jobName, "status", "RUNNING");
    }
}
