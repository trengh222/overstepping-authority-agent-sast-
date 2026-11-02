package com.example.shop;

/** D6 样本：查询对象（setter 注入污点后跨过程传给 Mapper）。 */
public interface StatisticsService {
    Object findListByPage(Query query);
}
