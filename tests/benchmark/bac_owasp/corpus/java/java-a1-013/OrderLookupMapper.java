package com.bac.java_a1_013;

import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface OrderLookupMapper {

    @Select("select id, order_no, user_id, amount from orders where order_no = #{orderNo}")
    Map<String, Object> selectByOrderNo(@Param("orderNo") String orderNo);
}
