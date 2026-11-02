package com.bac.java_a1_006;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface MessageMapper {

    @Select("select id, user_id, title, body from messages where user_id = #{userId}")
    List<Map<String, Object>> selectByUserId(@Param("userId") Long userId);
}
