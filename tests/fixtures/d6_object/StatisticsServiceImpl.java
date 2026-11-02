package com.example.shop;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/** D6 样本：实现类把查询对象继续传给 Mapper。 */
@Service
public class StatisticsServiceImpl implements StatisticsService {

    @Autowired
    private StatisticsMapper statisticsMapper;

    @Override
    public Object findListByPage(Query query) {
        return statisticsMapper.selectList(query);
    }
}
