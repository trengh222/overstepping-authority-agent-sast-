package com.bac.java_a1_024;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class MessageService {

    private final JdbcTemplate jdbcTemplate;

    public MessageService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Map<String, Object> findOwnedMessage(Long messageId, String username) {
        return jdbcTemplate.queryForMap(
                "select m.id, m.user_id, m.title, m.body from messages m "
                        + "join users u on u.id = m.user_id where m.id = ? and u.username = ?",
                messageId, username);
    }
}
