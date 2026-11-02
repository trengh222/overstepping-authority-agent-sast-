package com.example.store;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 继承链样本：字段声明类型是顶层接口 BaseStore，
 * 真实实现是 AssetStoreImpl（BaseStore ← AssetStore ← AssetStoreImpl）。
 */
@RestController
@RequestMapping("/api/assets")
public class AssetController {

    @Autowired
    private BaseStore baseStore;

    @GetMapping("/{assetId}")
    public Object detail(@PathVariable("assetId") Long assetId) {
        return baseStore.getById(assetId);
    }
}
