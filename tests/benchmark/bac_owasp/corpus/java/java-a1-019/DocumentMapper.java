package com.bac.java_a1_019;

import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface DocumentMapper {

    @Select("select id, owner_id, name, storage_key from documents "
            + "where id = #{docId} and owner_id = #{userId}")
    Map<String, Object> selectOwned(@Param("docId") Long docId, @Param("userId") Long userId);
}
