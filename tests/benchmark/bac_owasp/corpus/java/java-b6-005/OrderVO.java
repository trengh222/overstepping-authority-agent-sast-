package com.bac.java_b6_005;

public class OrderVO {

    private final Long id;
    private final String orderNo;
    private final String status;
    private final String totalAmount;

    public OrderVO(Long id, String orderNo, String status, String totalAmount) {
        this.id = id;
        this.orderNo = orderNo;
        this.status = status;
        this.totalAmount = totalAmount;
    }

    public Long getId() {
        return id;
    }

    public String getOrderNo() {
        return orderNo;
    }

    public String getStatus() {
        return status;
    }

    public String getTotalAmount() {
        return totalAmount;
    }
}
