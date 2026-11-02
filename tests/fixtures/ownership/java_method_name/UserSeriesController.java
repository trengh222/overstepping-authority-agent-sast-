package com.example.shop;

import com.example.shop.service.SeriesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/** D2 样本：方法名含 User 不再自动视为归属约束，以实参是否为当前用户为准。 */
@RestController
@RequestMapping("/api/series")
public class UserSeriesController {

    @Autowired
    private SeriesService seriesService;

    // 真漏洞：userId 来自客户端路径参数（不是当前用户）→ 应产出 A1
    @GetMapping("/{userId}")
    public Object load(@PathVariable("userId") Long userId) {
        return seriesService.getUserAllSeries(userId);
    }

    // 安全：实参 principal 是当前用户来源 → 有归属约束，不应产出
    @GetMapping("/mine/{userId}")
    public Object loadMine(@PathVariable("userId") Long userId, Principal principal) {
        return seriesService.getUserAllSeriesAndId(principal.getName(), userId);
    }

    // 安全：当前用户来源先赋给局部变量，再作为归属实参 → 应能跨语句识别
    @GetMapping("/token/{userId}")
    public Object loadToken(@PathVariable("userId") Long userId) {
        Long uid = tokenUserInfoDto.getUserId();
        return seriesService.getUserAllSeriesAndId(uid, userId);
    }
}
