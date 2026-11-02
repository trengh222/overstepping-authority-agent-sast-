package com.bac.java_a1_012;

import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface ReviewMapper {

    @Select("select id, user_id, product_id, rating, content from reviews where id = #{reviewId}")
    Map<String, Object> selectReview(@Param("reviewId") Long reviewId);
}
