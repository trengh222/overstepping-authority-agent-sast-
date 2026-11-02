package com.bac.java_a4_002;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/wallet")
public class WalletBalanceController {

    private final JdbcTemplate jdbcTemplate;

    public WalletBalanceController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/balance")
    public Map<String, Object> balance(@RequestParam("userId") Long userId) {
        return jdbcTemplate.queryForMap(
                "select user_id, available_balance, frozen_balance from wallets where user_id = ?", userId);
    }
}
