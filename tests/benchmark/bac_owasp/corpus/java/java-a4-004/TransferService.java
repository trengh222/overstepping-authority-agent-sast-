package com.bac.java_a4_004;

import java.math.BigDecimal;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TransferService {

    private final JdbcTemplate jdbcTemplate;

    public TransferService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional
    public Map<String, Object> transfer(Long fromUserId, Long toUserId, BigDecimal amount) {
        jdbcTemplate.update("update wallets set available_balance = available_balance - ? where user_id = ?",
                amount, fromUserId);
        jdbcTemplate.update("update wallets set available_balance = available_balance + ? where user_id = ?",
                amount, toUserId);
        jdbcTemplate.update(
                "insert into transfers (from_user_id, to_user_id, amount) values (?, ?, ?)",
                fromUserId, toUserId, amount);
        return Map.<String, Object>of(
                "from", fromUserId, "to", toUserId, "amount", amount, "status", "SUCCESS");
    }
}
