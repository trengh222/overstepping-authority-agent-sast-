package com.bac.gen.invoices_pos;

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1：路径参数 id 直接查库并返回，没有任何归属校验。 */
@RestController
@RequestMapping("/api/invoices")
public class InvoiceController {

    @Resource
    private InvoiceService invoicesService;

    @GetMapping("/{id}")
    public Invoice detail(@PathVariable("id") Long id) {
        return invoicesService.getById(id);
    }
}
