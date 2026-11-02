package com.bac.java_a1_018;

import java.util.Map;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class InvoiceService {

    private final JdbcTemplate jdbcTemplate;

    public InvoiceService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Optional<Map<String, Object>> findOwned(Long invoiceId, Long userId) {
        return jdbcTemplate.query(
                        "select id, user_id, invoice_no, amount from invoices where id = ? and user_id = ?",
                        (rs, rowNum) -> Map.<String, Object>of(
                                "id", rs.getLong("id"),
                                "user_id", rs.getLong("user_id"),
                                "invoice_no", rs.getString("invoice_no"),
                                "amount", rs.getBigDecimal("amount")),
                        invoiceId, userId)
                .stream()
                .findFirst();
    }
}
