package com.bac.java_a1_026;

import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface OrderLookupMapper {

    @Select("select id, order_no, user_id, amount from orders "
            + "where order_no = #{orderNo} and user_id = #{userId}")
    Map<String, Object> selectOwnedByOrderNo(@Param("orderNo") String orderNo,
                                             @Param("userId") Long userId);
}
