package com.bac.java_a1_005;

import java.util.Map;

import org.springframework.stereotype.Service;

@Service
public class PaymentService {

    private final PaymentMapper paymentMapper;

    public PaymentService(PaymentMapper paymentMapper) {
        this.paymentMapper = paymentMapper;
    }

    public Map<String, Object> findPayment(Long paymentId) {
        return paymentMapper.selectPayment(paymentId);
    }
}
