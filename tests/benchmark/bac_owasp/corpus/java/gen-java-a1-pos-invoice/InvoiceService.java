package com.bac.gen.invoices_pos;

/** 无所有权过滤：按主键直接取。 */
public class InvoiceService {

    public Invoice getById(Long id) {
        return InvoiceMapper.selectById(id);
    }
}
