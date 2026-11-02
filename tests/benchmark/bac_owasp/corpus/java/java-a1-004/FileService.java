package com.bac.java_a1_004;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class FileService {

    private final JdbcTemplate jdbcTemplate;

    public FileService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Map<String, Object> load(Long projectId, Long fileId) {
        return jdbcTemplate.queryForMap(
                "select id, project_id, storage_key from project_files where id = ? and project_id = ?",
                fileId, projectId);
    }
}
