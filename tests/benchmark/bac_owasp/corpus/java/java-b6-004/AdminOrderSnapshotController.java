package com.bac.java_b6_004;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
@RequestMapping("/api/admin/orders")
public class AdminOrderSnapshotController {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public AdminOrderSnapshotController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/{id}/snapshot")
    public String snapshot(@PathVariable("id") Long id) throws Exception {
        OrderEntity order = jdbcTemplate.queryForObject(
                "select id, order_no, total_amount, buyer_phone, buyer_email from orders where id = ?",
                (rs, rowNum) -> {
                    OrderEntity entity = new OrderEntity();
                    entity.id = rs.getLong("id");
                    entity.orderNo = rs.getString("order_no");
                    entity.totalAmount = rs.getBigDecimal("total_amount");
                    entity.buyerPhone = rs.getString("buyer_phone");
                    entity.buyerEmail = rs.getString("buyer_email");
                    return entity;
                },
                id);
        return objectMapper.writeValueAsString(order);
    }

    public static class OrderEntity {
        public Long id;
        public String orderNo;
        public java.math.BigDecimal totalAmount;
        public String buyerPhone;
        public String buyerEmail;
    }
}
