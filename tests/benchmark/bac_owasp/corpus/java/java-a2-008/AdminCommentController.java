package com.bac.java_a2_008;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/comments")
public class AdminCommentController {

    private final JdbcTemplate jdbcTemplate;

    public AdminCommentController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @DeleteMapping("/{id}")
    public Map<String, Object> remove(@PathVariable("id") Long id) {
        jdbcTemplate.update("delete from comments where id = ?", id);
        return Map.<String, Object>of("removed", id);
    }
}
