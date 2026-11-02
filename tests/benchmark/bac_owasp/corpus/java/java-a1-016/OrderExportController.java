package com.bac.java_a1_016;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/orders")
public class OrderExportController {

    private final OrderExportService orderExportService;

    public OrderExportController(OrderExportService orderExportService) {
        this.orderExportService = orderExportService;
    }

    @PostMapping("/export")
    public List<Map<String, Object>> export(@RequestBody List<Long> orderIds) {
        return orderExportService.exportSelected(orderIds);
    }
}
