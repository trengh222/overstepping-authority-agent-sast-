package com.bac.java_a1_015;

import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface DocumentVersionMapper {

    @Select("select id, doc_id, owner_id, content_ref from document_versions "
            + "where doc_id = #{docId} and id = #{versionId}")
    Map<String, Object> selectVersion(@Param("docId") Long docId,
                                      @Param("versionId") Long versionId);
}
