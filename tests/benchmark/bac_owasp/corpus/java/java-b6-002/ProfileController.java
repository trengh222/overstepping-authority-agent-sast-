package com.bac.java_b6_002;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private final JdbcTemplate jdbcTemplate;

    public ProfileController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping
    public Account current(HttpSession session) {
        Long userId = (Long) session.getAttribute("LOGIN_USER_ID");
        if (userId == null) {
            throw new IllegalStateException("login required");
        }
        return jdbcTemplate.queryForObject(
                "select id, username, password, email, phone, api_token from users where id = ?",
                (rs, rowNum) -> {
                    Account account = new Account();
                    account.id = rs.getLong("id");
                    account.username = rs.getString("username");
                    account.password = rs.getString("password");
                    account.email = rs.getString("email");
                    account.phone = rs.getString("phone");
                    account.apiToken = rs.getString("api_token");
                    return account;
                },
                userId);
    }

    public static class Account {
        public Long id;
        public String username;
        public String password;
        public String email;
        public String phone;
        public String apiToken;
    }
}
