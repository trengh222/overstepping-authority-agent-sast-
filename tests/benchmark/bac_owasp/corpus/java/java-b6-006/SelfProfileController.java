package com.bac.java_b6_006;

import com.fasterxml.jackson.annotation.JsonIgnore;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api/me/profile")
public class SelfProfileController {

    private final JdbcTemplate jdbcTemplate;

    public SelfProfileController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping
    public MaskedProfile profile(HttpSession session) {
        Long userId = (Long) session.getAttribute("LOGIN_USER_ID");
        return jdbcTemplate.queryForObject(
                "select id, username, nickname, password, email, phone, api_token from users where id = ?",
                (rs, rowNum) -> {
                    MaskedProfile profile = new MaskedProfile();
                    profile.id = rs.getLong("id");
                    profile.username = rs.getString("username");
                    profile.nickname = rs.getString("nickname");
                    profile.password = rs.getString("password");
                    profile.email = rs.getString("email");
                    profile.phone = rs.getString("phone");
                    profile.apiToken = rs.getString("api_token");
                    return profile;
                },
                userId);
    }

    public static class MaskedProfile {
        public Long id;
        public String username;
        public String nickname;
        @JsonIgnore
        public String password;
        @JsonIgnore
        public String email;
        @JsonIgnore
        public String phone;
        @JsonIgnore
        public String apiToken;
    }
}
