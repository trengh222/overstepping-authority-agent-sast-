package com.bac.java_a1_014;

import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

@Mapper
public interface OrderCancelMapper {

    @Update("update orders set status = 'CANCELLED' where id = #{id}")
    int cancelById(@Param("id") Long id);

    @Select("select id, user_id, amount, status from orders where id = #{id}")
    Map<String, Object> selectById(@Param("id") Long id);
}
