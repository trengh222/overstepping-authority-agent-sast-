package com.example.store;

import org.springframework.beans.factory.annotation.Autowired;

/** 继承链样本：父类持有 Mapper 与真正的方法体。 */
public abstract class BaseAssetHandler {

    @Autowired
    protected AssetMapper assetMapper;

    protected Asset load(Long assetId) {
        return assetMapper.selectById(assetId);
    }
}
