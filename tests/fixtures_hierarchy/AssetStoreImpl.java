package com.example.store;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/** 继承链样本：唯一实现类，方法名叫 getById（不是 *Service 后缀）。 */
@Service
public class AssetStoreImpl implements AssetStore {

    @Autowired
    private AssetMapper assetMapper;

    @Override
    public Asset getById(Long assetId) {
        return assetMapper.selectById(assetId);
    }
}
