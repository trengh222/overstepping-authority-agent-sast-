package com.bac.java_a1_009;

import java.nio.charset.StandardCharsets;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class AttachmentService {

    private final JdbcTemplate jdbcTemplate;

    public AttachmentService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public byte[] readFile(Long attachmentId) {
        String storageKey = jdbcTemplate.queryForObject(
                "select storage_key from attachments where id = ?", String.class, attachmentId);
        return storageKey.getBytes(StandardCharsets.UTF_8);
    }
}
