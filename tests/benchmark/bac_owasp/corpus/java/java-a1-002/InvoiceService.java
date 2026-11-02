package com.bac.java_a1_002;

import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class InvoiceService {

    private final JdbcTemplate jdbcTemplate;

    public InvoiceService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Map<String, Object> loadInvoice(Long invoiceId) {
        return jdbcTemplate.queryForMap(
                "select id, user_id, invoice_no, amount from invoices where id = ?", invoiceId);
    }
}
