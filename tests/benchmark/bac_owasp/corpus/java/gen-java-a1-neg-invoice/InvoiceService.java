package com.bac.gen.invoices_neg;

/** 归属过滤：id + userId 双条件。 */
public class InvoiceService {

    public Invoice getByIdAndUserId(Long id, Long userId) {
        return InvoiceMapper.selectByIdAndUserId(id, userId);
    }
}
