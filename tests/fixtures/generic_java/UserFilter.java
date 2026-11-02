package com.example.generic;

/** 通用性验证样本：客户端可控的过滤对象（命名与任何特定项目无关）。 */
public class UserFilter {
    private String userId;
    private Integer pageNo;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public Integer getPageNo() {
        return pageNo;
    }

    public void setPageNo(Integer pageNo) {
        this.pageNo = pageNo;
    }
}
