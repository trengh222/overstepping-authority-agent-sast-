package com.example.generic;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/** 通用性验证样本：文章服务 → Mapper。 */
@Service
public class ArticleService {

    @Autowired
    private ArticleMapper articleMapper;

    public Article getById(Long articleId) {
        return articleMapper.selectById(articleId);
    }

    public int deleteById(Long articleId) {
        return articleMapper.deleteById(articleId);
    }
}
