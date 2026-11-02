package com.bac.java_a1_005;

import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface PaymentMapper {

    @Select("select id, user_id, order_id, card_no, amount from payments where id = #{paymentId}")
    Map<String, Object> selectPayment(@Param("paymentId") Long paymentId);
}
