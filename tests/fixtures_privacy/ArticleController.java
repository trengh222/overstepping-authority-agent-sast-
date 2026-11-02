package com.example.generic;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 公开资源隐私模型验证样本（POJO 无 @Entity，靠所有权模型声明）：
 * - /read 读文章详情：声明 PUBLIC 时属公开内容，不报 A1；
 * - /remove 删文章：公开资源不豁免写操作，仍报 A1。
 */
@RestController
@RequestMapping("/api/articles")
public class ArticleController {

    @Autowired
    private ArticleService articleService;

    @GetMapping("/{articleId}")
    public Object read(@PathVariable("articleId") Long articleId) {
        return articleService.getById(articleId);
    }

    @GetMapping("/remove/{articleId}")
    public Object remove(@PathVariable("articleId") Long articleId) {
        return articleService.deleteById(articleId);
    }
}
