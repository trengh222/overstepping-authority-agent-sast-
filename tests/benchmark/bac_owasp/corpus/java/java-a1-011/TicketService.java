package com.bac.java_a1_011;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class TicketService {

    private final JdbcTemplate jdbcTemplate;

    public TicketService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void updateTicket(Long ticketId, String title, String priority) {
        jdbcTemplate.update("update tickets set title = ?, priority = ? where id = ?",
                title, priority, ticketId);
    }

    public Map<String, Object> findById(Long ticketId) {
        return jdbcTemplate.queryForMap(
                "select id, reporter_id, assignee_id, title, priority from tickets where id = ?",
                ticketId);
    }
}
