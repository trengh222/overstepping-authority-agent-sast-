package com.example.store;

/** 继承链样本：顶层接口（没有命名约定可依赖，只能靠继承关系解析）。 */
public interface BaseStore {

    Asset getById(Long assetId);
}
