package com.example.generic;

/** 通用性验证样本：资源实体（含归属字段）。 */
public class Asset {
    private Long id;
    private String ownerId;

    public Long getId() {
        return id;
    }

    public String getOwnerId() {
        return ownerId;
    }
}
