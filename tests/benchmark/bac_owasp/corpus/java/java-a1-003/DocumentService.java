package com.bac.java_a1_003;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class DocumentService {

    private final JdbcTemplate jdbcTemplate;

    public DocumentService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Map<String, Object> rename(Long docId, String newName) {
        jdbcTemplate.update("update documents set name = ? where id = ?", newName, docId);
        return jdbcTemplate.queryForMap(
                "select id, owner_id, name from documents where id = ?", docId);
    }
}
