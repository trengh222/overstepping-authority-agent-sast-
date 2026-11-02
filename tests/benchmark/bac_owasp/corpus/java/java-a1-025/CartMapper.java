package com.bac.java_a1_025;

import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface CartMapper {

    @Delete("<script>delete from cart_items where user_id = #{userId} and id in "
            + "<foreach item='itemId' collection='itemIds' open='(' separator=',' close=')'>#{itemId}</foreach>"
            + "</script>")
    int deleteOwned(@Param("itemIds") List<Long> itemIds, @Param("userId") Long userId);
}
