package com.example.shop;

import com.example.shop.entity.Order;
import com.example.shop.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/** IDOR 正样本 + 仓库配置缺少 shipment.export.enabled → 只降级，不关闭。 */
@RestController
@RequestMapping("/api")
public class ShipmentController {

    @Autowired
    private OrderService orderService;

    // [A1] 仓库配置键 shipment.export.enabled 缺失
    @GetMapping("/shipment/{oid}")
    public Order exportShipment(@PathVariable("oid") Long oid) {
        if (!flags.isEnabled("shipment.export.enabled")) {
            throw new IllegalStateException("export disabled");
        }
        return orderService.findById(oid);
    }
}
