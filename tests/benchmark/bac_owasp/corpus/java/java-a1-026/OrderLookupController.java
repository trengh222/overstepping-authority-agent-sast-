package com.bac.java_a1_026;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api/orders/no")
public class OrderLookupController {

    private final OrderLookupMapper orderLookupMapper;

    public OrderLookupController(OrderLookupMapper orderLookupMapper) {
        this.orderLookupMapper = orderLookupMapper;
    }

    @GetMapping("/{orderNo}")
    public Map<String, Object> byOrderNo(@PathVariable("orderNo") String orderNo, HttpSession session) {
        Long currentUserId = (Long) session.getAttribute("LOGIN_USER_ID");
        return orderLookupMapper.selectOwnedByOrderNo(orderNo, currentUserId);
    }
}
