package com.bac.java_a1_001;

import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface OrderMapper {

    @Select("select id, user_id, amount, status from orders where id = #{id}")
    Map<String, Object> selectById(@Param("id") Long id);
}
