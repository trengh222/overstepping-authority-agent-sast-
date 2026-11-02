package com.bac.java_a1_021;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class ProjectFileService {

    private final JdbcTemplate jdbcTemplate;

    public ProjectFileService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public boolean ownsProject(Long projectId, Long userId) {
        Integer count = jdbcTemplate.queryForObject(
                "select count(*) from projects where id = ? and owner_id = ?",
                Integer.class, projectId, userId);
        return count != null && count > 0;
    }

    public Map<String, Object> loadFile(Long projectId, Long fileId) {
        return jdbcTemplate.queryForMap(
                "select id, project_id, storage_key from project_files where id = ? and project_id = ?",
                fileId, projectId);
    }
}
