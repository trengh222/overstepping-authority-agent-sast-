package com.example.generic;

/** 通用性验证样本：普通 POJO（无 @Entity），隐私由所有权模型声明。 */
public class Article {

    private Long articleId;
    private String authorId;
    private String title;
    private Integer status;

    public Long getArticleId() {
        return articleId;
    }

    public String getAuthorId() {
        return authorId;
    }
}
