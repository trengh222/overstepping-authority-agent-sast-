package com.bac.java_a2_006;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/notify")
public class AdminNotifyController {

    private final JdbcTemplate jdbcTemplate;

    public AdminNotifyController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostMapping("/broadcast")
    public Map<String, Object> broadcast(@RequestBody NotifyRequest request) {
        int sent = jdbcTemplate.update(
                "insert into notifications (user_id, title, body, created_at) "
                        + "select id, ?, ?, now() from users",
                request.getTitle(), request.getBody());
        return Map.<String, Object>of("sent", sent);
    }

    public static class NotifyRequest {

        private String title;
        private String body;

        public String getTitle() {
            return title;
        }

        public void setTitle(String title) {
            this.title = title;
        }

        public String getBody() {
            return body;
        }

        public void setBody(String body) {
            this.body = body;
        }
    }
}
