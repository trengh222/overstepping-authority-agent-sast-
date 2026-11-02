package com.bac.java_a1_010;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface AddressMapper {

    @Delete("delete from addresses where id = #{addressId}")
    int deleteById(@Param("addressId") Long addressId);
}
