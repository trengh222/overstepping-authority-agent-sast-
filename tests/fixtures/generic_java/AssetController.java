package com.example.generic;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;

/**
 * 通用性验证样本（文件资源 + 显式归属校验），命名与任何特定项目无关：
 * - 客户端可控路径 → 文件读取 sink（任意文件读取）；
 * - 写文件（FileOutputStream）不算越权读；
 * - 归属字段与当前用户比较 + 拒绝分支 → 归属约束成立。
 */
@RestController
@RequestMapping("/api/assets")
public class AssetController {

    @Autowired
    private AssetService assetService;

    // 任意文件读取：path 直接落到 FileInputStream
    @GetMapping("/read")
    public byte[] read(String path) throws IOException {
        try (FileInputStream in = new FileInputStream(path)) {
            return in.readAllBytes();
        }
    }

    // 写文件：不应作为「读取他人资源」的越权
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/write")
    public void store(String path, InputStream content) throws IOException {
        java.nio.file.Files.copy(content, java.nio.file.Paths.get(path));
    }

    // 显式归属校验：owner 字段与当前用户比较，不匹配直接抛错
    @GetMapping("/{assetId}")
    public Object detail(@PathVariable("assetId") Long assetId, Principal principal) {
        Asset asset = assetService.getById(assetId);
        if (asset == null || !asset.getOwnerId().equals(principal.getName())) {
            throw new IllegalStateException("not owner");
        }
        return asset;
    }
}
