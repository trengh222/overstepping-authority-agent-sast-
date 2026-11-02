package com.example.store;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 继承链样本：子类未覆写 load()，方法体在父类 BaseAssetHandler 里。 */
@RestController
@RequestMapping("/api/legacy")
public class ChildAssetHandler extends BaseAssetHandler {

    @GetMapping("/{assetId}")
    public Object detail(@PathVariable("assetId") Long assetId) {
        return load(assetId);
    }
}
