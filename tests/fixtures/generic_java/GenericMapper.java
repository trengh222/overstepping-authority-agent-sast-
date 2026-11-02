package com.example.generic;

/** 通用性验证样本：数据访问接口（无实现体，接收者类型即数据访问事实）。 */
public interface GenericMapper {
    Object selectById(Long id);

    Object selectList(UserFilter filter);
}
