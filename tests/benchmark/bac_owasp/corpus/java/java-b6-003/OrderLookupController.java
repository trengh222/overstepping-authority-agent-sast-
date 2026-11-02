package com.bac.java_b6_003;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/orders")
public class OrderLookupController {

    private final JdbcTemplate jdbcTemplate;

    public OrderLookupController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/{id}")
    public OrderEntity lookup(@PathVariable("id") Long id) {
        return jdbcTemplate.queryForObject(
                "select id, order_no, total_amount, status, buyer_name, buyer_phone, buyer_email "
                        + "from orders where id = ?",
                (rs, rowNum) -> {
                    OrderEntity order = new OrderEntity();
                    order.id = rs.getLong("id");
                    order.orderNo = rs.getString("order_no");
                    order.totalAmount = rs.getBigDecimal("total_amount");
                    order.status = rs.getString("status");
                    order.buyerName = rs.getString("buyer_name");
                    order.buyerPhone = rs.getString("buyer_phone");
                    order.buyerEmail = rs.getString("buyer_email");
                    return order;
                },
                id);
    }

    public static class OrderEntity {
        public Long id;
        public String orderNo;
        public java.math.BigDecimal totalAmount;
        public String status;
        public String buyerName;
        public String buyerPhone;
        public String buyerEmail;
    }
}
