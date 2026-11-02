package com.example.shop;

import com.example.shop.entity.Order;
import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/** 配置开关正样本：handler 读取 feature 开关（未声明 → needs_config / 全局声明 false → unreachable）。 */
@RestController
@RequestMapping("/api")
public class ExportController {

    @Autowired
    private OrderService orderService;

    // [A1] 一元条件读取配置开关：符号执行不得崩溃（未解释条件 → unsound 保持 LIKELY）
    @GetMapping("/export/{oid}")
    public Order exportOrder(@PathVariable("oid") Long oid) {
        if (!featureFlags.isEnabled("export.enabled")) {
            throw new IllegalStateException("export disabled");
        }
        return orderService.findById(oid);
    }
}
