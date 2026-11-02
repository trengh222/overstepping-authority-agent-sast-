package com.example.generic;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/** 通用性验证样本：资源服务 → Mapper。 */
@Service
public class AssetService {

    @Autowired
    private AssetMapper assetMapper;

    public Asset getById(Long assetId) {
        return assetMapper.selectById(assetId);
    }
}
