package com.bac.java_a1_022;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class TicketService {

    private final JdbcTemplate jdbcTemplate;

    public TicketService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public boolean deleteOwnedTicket(Long ticketId, Long userId) {
        int affected = jdbcTemplate.update(
                "delete from tickets where id = ? and reporter_id = ?", ticketId, userId);
        return affected > 0;
    }
}
