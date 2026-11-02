package com.example.other;

import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 注册可达正样本：包不在扫描根内，但被 @Import 引用 → 已注册。 */
@RestController
@RequestMapping("/api/order")
public class ImportedController {

    @Autowired
    private OrderService orderService;

    @GetMapping("/{id}")
    public Object getOrder(@PathVariable("id") Long id) {
        return orderService.findById(id);
    }
}
