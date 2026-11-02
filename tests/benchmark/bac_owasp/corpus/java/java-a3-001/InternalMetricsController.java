package com.bac.java_a3_001;

import java.lang.management.ManagementFactory;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/metrics")
public class InternalMetricsController {

    private final JdbcTemplate jdbcTemplate;

    public InternalMetricsController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping
    public Map<String, Object> metrics() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("heapUsed", Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory());
        result.put("uptime", ManagementFactory.getRuntimeMXBean().getUptime());
        result.put("activeSessions",
                jdbcTemplate.queryForObject("select count(*) from user_sessions", Integer.class));
        return result;
    }
}
