"""通用性验证：规则不依赖任何特定项目的命名约定。

运行：python -m pytest tests/test_generic_rules.py -q

用与 easylive/任何项目无关的命名，验证：
- 本类方法（无论叫什么）不是数据 sink，但参数内真实 DAO 调用仍被追踪；
- 无注解的任意对象参数（非 Query 后缀）按 Spring query/form 绑定为污点源；
- 自定义鉴权注解通过「参数语义开关」识别，不依赖注解名；
- 创建类 handler 不产生 A1。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.extractor.java import is_scalar_param_type

_FIX = _REPO / "tests" / "fixtures" / "generic_java"


def _cands():
    cands, _ = cli.scan(_FIX)
    return cands


# ---------------- 包装 / 本类方法 ----------------

def test_local_wrapper_is_not_sink_but_inner_dao_traced():
    a1 = [c for c in _cands() if c.subtype == "A1" and c.endpoint.path == "/api/generic/{id}"]
    assert len(a1) == 1, "wrapPayload 包装行不应额外产生候选"
    assert any("findById" in f for f in a1[0].access.flow), "内层 DAO 调用应被追踪"
    assert "wrapPayload" not in a1[0].access.sink_snippet


def test_local_helper_without_dao_not_reported():
    paths = {c.endpoint.path for c in _cands() if c.subtype == "A1"}
    assert "/api/generic/local/{id}" not in paths, "本类无 DAO 的辅助方法不应产出候选"


# ---------------- 对象参数污点源 ----------------

def test_non_query_object_param_is_taint_source():
    a1 = [c for c in _cands() if c.subtype == "A1" and c.endpoint.path == "/api/generic/search"]
    assert a1, "无注解对象参数（非 Query 后缀）应作为污点源"
    ep = a1[0].endpoint
    p = [x for x in ep.params if x.name == "filter"][0]
    assert p.source.value == "QUERY"


def test_scalar_param_classification():
    assert is_scalar_param_type("String")
    assert is_scalar_param_type("java.lang.Long")
    assert is_scalar_param_type("int")
    assert is_scalar_param_type("MultipartFile")
    assert not is_scalar_param_type("UserFilter")
    assert not is_scalar_param_type("com.example.UserFilter")
    assert not is_scalar_param_type("StatisticsInfo")


# ---------------- 自定义鉴权注解（无语义开关则不算） ----------------

def test_auth_flag_annotation_recognized_by_semantics():
    ep = [e for e in _cands() if e.endpoint.path == "/api/generic/protected/{id}"][0].endpoint
    assert ep.auth.present and ep.auth.mechanism.value == "ANNOTATION"
    assert "requireAuth" in (ep.auth.role_or_perm or "")


def test_plain_annotation_not_auth():
    ep = [e for e in _cands() if e.endpoint.path == "/api/generic/{id}"][0].endpoint
    assert not ep.auth.present, "普通注解（无鉴权语义开关）不应算鉴权"


# ---------------- 文件读取 sink ----------------

def test_client_path_to_file_read():
    hits = [c for c in _cands()
            if c.subtype == "A1" and c.endpoint.path == "/api/assets/read"]
    assert hits, "客户端可控 path 流向 FileInputStream 应报任意文件读取"
    assert hits[0].access.entity == "File"
    assert "FileInputStream" in hits[0].access.sink_snippet or ".java:" in hits[0].access.sink_snippet


def test_file_write_not_reported():
    paths = {c.endpoint.path for c in _cands() if c.subtype == "A1"}
    assert "/api/assets/write" not in paths, "写文件不是越权读取"


# ---------------- 显式归属校验 ----------------

def test_explicit_owner_comparison_suppresses():
    paths = {c.endpoint.path for c in _cands() if c.subtype == "A1"}
    assert "/api/assets/{assetId}" not in paths, \
        "归属字段与当前用户比较 + 拒绝分支 → 有归属约束，不应报 A1"


def test_explicit_ownership_detector():
    from access_scan.dataflow.taint import java_explicit_ownership

    class Ctx:
        node = None
        lines = ["if (!x.getOwnerId().equals(currentUser.getUserId())) {",
                 "    throw new IllegalStateException();",
                 "}",
                 "return x;"]

        class _N:  # 模拟 tree-sitter 节点的 start/end_point
            start_point = (0, 0)
            end_point = (3, 0)

        @property
        def method_node(self):
            return self._N()

    c = Ctx()
    c.node = c._N()
    assert java_explicit_ownership(c)


# ---------------- 集合 API 不算特权写操作 ----------------

_COLL_SRC = b"""
package x;
import java.util.*;
public class C {
    public Object load(String id) {
        List<String> rows = new ArrayList<>();
        rows.addAll(Arrays.asList(id));
        rows.add(id);
        return rows;
    }
    public void removeItem(String id) {
        itemService.removeById(id);
    }
}
"""


def test_collection_api_is_not_privileged_write():
    from access_scan.extractor.java import JavaExtractor, find_write_ops

    ext = JavaExtractor()
    ast = ext.parse(_COLL_SRC)
    cls = next(ext._iter_classes(ast.root_node))
    methods = [m for m in cls.child_by_field_name("body").named_children
               if m.type == "method_declaration"]
    load = [m for m in methods if _method_name(m) == "load"][0]
    remove = [m for m in methods if _method_name(m) == "removeItem"][0]
    assert find_write_ops(load) == [], "List.addAll/add 是集合 API，不是业务写操作"
    assert find_write_ops(remove), "业务删除调用仍应识别为特权写"


def _method_name(method_node):
    n = method_node.child_by_field_name("name")
    return n.text.decode() if n is not None else ""
