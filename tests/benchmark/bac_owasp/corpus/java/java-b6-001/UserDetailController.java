package com.bac.java_b6_001;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserDetailController {

    private final JdbcTemplate jdbcTemplate;

    public UserDetailController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @RequestMapping("/api/users/{id}")
    public User detail(@PathVariable("id") Long id) {
        return jdbcTemplate.queryForObject(
                "select id, username, password, email, phone, id_card from users where id = ?",
                (rs, rowNum) -> {
                    User user = new User();
                    user.id = rs.getLong("id");
                    user.username = rs.getString("username");
                    user.password = rs.getString("password");
                    user.email = rs.getString("email");
                    user.phone = rs.getString("phone");
                    user.idCard = rs.getString("id_card");
                    return user;
                },
                id);
    }

    public static class User {
        public Long id;
        public String username;
        public String password;
        public String email;
        public String phone;
        public String idCard;
    }
}
