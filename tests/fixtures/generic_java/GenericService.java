package com.example.generic;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/** 通用性验证样本：Service 实现类 → Mapper（真实数据访问）。 */
@Service
public class GenericService {

    @Autowired
    private GenericMapper genericMapper;

    public Object findById(Long id) {
        return genericMapper.selectById(id);
    }

    public Object findListByFilter(UserFilter filter) {
        return genericMapper.selectList(filter);
    }
}
