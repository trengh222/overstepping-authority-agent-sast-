package com.example.shop;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/** D6 样本：ServiceImpl 内部调用 Mapper；污点应能穿过接口 → 实现 → Mapper。 */
@Service
public class SeriesServiceImpl implements SeriesService {

    @Autowired
    private SeriesMapper seriesMapper;

    @Override
    public Object load(Long id) {
        return seriesMapper.selectById(id);
    }
}
