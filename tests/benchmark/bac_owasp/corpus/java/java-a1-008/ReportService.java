package com.bac.java_a1_008;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class ReportService {

    private final JdbcTemplate jdbcTemplate;

    public ReportService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public String exportCsv(Long reportId) {
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "select id, user_id, revenue, orders from reports where id = ?", reportId);
        StringBuilder csv = new StringBuilder("id,user_id,revenue,orders\n");
        for (Map<String, Object> row : rows) {
            csv.append(row.get("id")).append(',')
                    .append(row.get("user_id")).append(',')
                    .append(row.get("revenue")).append(',')
                    .append(row.get("orders")).append('\n');
        }
        return csv.toString();
    }
}
