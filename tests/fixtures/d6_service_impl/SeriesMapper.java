package com.example.shop;

/** D6 样本：MyBatis Mapper 接口（无实现体，接收者类型即数据访问事实）。 */
public interface SeriesMapper {
    Object selectById(Long id);
}
