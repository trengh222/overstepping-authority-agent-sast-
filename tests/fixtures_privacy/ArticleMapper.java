package com.example.generic;

/** 通用性验证样本：文章 Mapper。 */
public interface ArticleMapper {

    Article selectById(Long articleId);

    int deleteById(Long articleId);
}
