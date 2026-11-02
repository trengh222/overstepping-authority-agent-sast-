package com.bac.java_a1_020;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface InvoiceMapper {

    @Select("select id, user_id, invoice_no, amount from invoices where user_id = #{userId}")
    List<Map<String, Object>> selectByUserId(@Param("userId") Long userId);
}
