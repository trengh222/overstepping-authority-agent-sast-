package com.example.generic;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 通用性验证样本：所有命名都与任何特定项目无关。
 * - 本类包装方法叫 wrapPayload（不叫 getSuccessResponse*），不应作为数据 sink；
 * - 无注解对象参数叫 UserFilter（无 Query 后缀），应作为客户端可控污点源；
 * - 自定义鉴权注解叫 @NeedLogin(requireAuth = true)，无切面也应识别。
 */
@RestController
@RequestMapping("/api/generic")
public class GenericController {

    @Autowired
    private GenericService genericService;

    // 包装方法：真实 sink 是内层 genericService.findById
    @GetMapping("/{id}")
    public Object detail(@PathVariable("id") Long id) {
        return wrapPayload(genericService.findById(id));
    }

    // 无注解对象参数（非 Query 后缀）→ query/form 绑定，客户端可控
    @GetMapping("/search")
    public Object search(UserFilter filter) {
        return genericService.findListByFilter(filter);
    }

    // 仅本类辅助方法，不含 DAO 调用 → 不应产出候选
    @GetMapping("/local/{id}")
    public Object local(@PathVariable("id") Long id) {
        return renderLocal(id);
    }

    @NeedLogin(requireAuth = true)
    @GetMapping("/protected/{id}")
    public Object protectedDetail(@PathVariable("id") Long id) {
        return genericService.findById(id);
    }

    private Object wrapPayload(Object body) {
        return body;
    }

    private Object renderLocal(Long id) {
        return "local-" + id;
    }
}
