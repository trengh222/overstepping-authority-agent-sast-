"""D3 包装 sink + D5 自定义鉴权注解测试（通用规则，不依赖具体命名）。

运行：python -m pytest tests/test_d3_d5.py -q
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.dataflow.taint import _STRONG_ID_LOOKUP_RE
from access_scan.extractor.java import collect_custom_auth_annotations
from access_scan.ir import AuthMechanism

_FIX = _REPO / "tests" / "fixtures"


# ---------------- D3 ----------------

def test_wrapper_patterns():
    assert not _STRONG_ID_LOOKUP_RE.search("getSuccessResponseVO")
    assert not _STRONG_ID_LOOKUP_RE.search("readFile")
    assert _STRONG_ID_LOOKUP_RE.search("findById")
    assert _STRONG_ID_LOOKUP_RE.search("findByUsername")


def test_wrapper_not_reported_as_sink():
    cands, _ = cli.scan(_FIX / "d3_wrapper")
    a1 = [c for c in cands if c.subtype == "A1"]
    paths = [c.endpoint.path for c in a1]
    assert paths.count("/api/order/{id}") == 1, "包装行不应产生第二条候选"
    assert "/api/order/file/{id}" not in paths, "readFile 包装不应被当作 sink"
    c = [x for x in a1 if x.endpoint.path == "/api/order/{id}"][0]
    assert any("findById" in f for f in c.access.flow), "证据链应落在真实 DAO 调用"


# ---------------- D5 ----------------

def test_collect_custom_auth_annotations():
    text = ('@Aspect\n@Component\npublic class A {\n'
            '  @Before("@annotation(com.x.RequireLogin)")\n'
            '  public void check() { String token = req.getHeader("token"); redis.get(token); }\n}')
    assert collect_custom_auth_annotations([("java", text)]) == {"RequireLogin"}


def test_collect_ignores_non_auth_aspect():
    text = '@Before("@annotation(com.x.LogIt)")\npublic void log() { System.out.println(1); }'
    assert collect_custom_auth_annotations([("java", text)]) == set()


def _auth(path: str):
    cands, _ = cli.scan(_FIX / "d5_auth")
    c = [x for x in cands if x.endpoint.path == path and x.subtype == "A1"][0]
    return c.endpoint.auth


def test_checklogin_true_recognized():
    auth = _auth("/file/uploadVideo")
    assert auth.present and auth.mechanism == AuthMechanism.ANNOTATION
    assert "checkLogin" in (auth.role_or_perm or "")


def test_checklogin_false_not_auth():
    auth = _auth("/file/public")
    assert not auth.present, "checkLogin=false 不算鉴权"


def test_custom_aspect_annotation_recognized():
    auth = _auth("/file/custom/{id}")
    assert auth.present and auth.annotation == "RequireLogin"
