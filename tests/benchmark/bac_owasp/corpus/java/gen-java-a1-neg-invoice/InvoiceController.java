package com.bac.gen.invoices_neg;

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1 负例：查询在 service 层绑定当前登录用户。 */
@RestController
@RequestMapping("/api/invoices")
public class InvoiceController {

    @Resource
    private InvoiceService invoicesService;

    @GetMapping("/{id}")
    public Invoice detail(@PathVariable("id") Long id) {
        Long uid = CurrentUser.id();
        return invoicesService.getByIdAndUserId(id, uid);
    }
}
