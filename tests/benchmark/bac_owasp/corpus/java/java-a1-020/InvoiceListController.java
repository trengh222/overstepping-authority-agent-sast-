package com.bac.java_a1_020;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api/invoices")
public class InvoiceListController {

    private final InvoiceMapper invoiceMapper;

    public InvoiceListController(InvoiceMapper invoiceMapper) {
        this.invoiceMapper = invoiceMapper;
    }

    @GetMapping
    public List<Map<String, Object>> list(@RequestParam(value = "userId", required = false) Long userId,
                                          HttpSession session) {
        Long currentUserId = (Long) session.getAttribute("LOGIN_USER_ID");
        return invoiceMapper.selectByUserId(currentUserId);
    }
}
