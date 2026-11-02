package com.bac.java_a4_006;

import java.util.Date;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Service
public class JwtService {

    private final JdbcTemplate jdbcTemplate;

    private static final String SECRET = "c2VjcmV0LWtleS1mb3ItamF2YS1jb3JwdXMtdGVzdA==";

    public JwtService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Claims parse(String token) {
        try {
            Claims claims = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
            if (claims.getExpiration() == null || claims.getExpiration().before(new Date())) {
                return null;
            }
            return claims;
        } catch (RuntimeException ex) {
            return null;
        }
    }

    public Map<String, Object> loadUser(Long userId) {
        return jdbcTemplate.queryForMap("select id, username, role from users where id = ?", userId);
    }
}
