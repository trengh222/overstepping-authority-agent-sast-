package com.bac.java_a1_013;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/orders/no")
public class OrderLookupController {

    private final OrderLookupMapper orderLookupMapper;

    public OrderLookupController(OrderLookupMapper orderLookupMapper) {
        this.orderLookupMapper = orderLookupMapper;
    }

    @GetMapping("/{orderNo}")
    public Map<String, Object> byOrderNo(@PathVariable("orderNo") String orderNo) {
        return orderLookupMapper.selectByOrderNo(orderNo);
    }
}
