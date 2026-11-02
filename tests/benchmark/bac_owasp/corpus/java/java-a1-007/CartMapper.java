package com.bac.java_a1_007;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface CartMapper {

    @Select("<script>"
            + "select id, user_id, product_id, quantity from cart_items where id in "
            + "<foreach item='itemId' collection='itemIds' open='(' separator=',' close=')'>#{itemId}</foreach>"
            + "</script>")
    List<Map<String, Object>> selectByIds(@Param("itemIds") List<Long> itemIds);
}
