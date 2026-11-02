"""通用数据访问识别（sink 放宽）测试。

运行：python -m pytest tests/test_sink_extension.py -q
覆盖两类新 sink 信号：
- #1 原生 SQL 文本：调用实参含 SELECT/UPDATE/DELETE/INSERT ... FROM 即数据访问 sink
  （不依赖方法名白名单/接收者类型，覆盖 node-postgres / JDBC / Knex raw）；
- #2 数据访问接收者：接收者名像 DAO（db/repo/dao/mapper 及 orderRepo/user_repo 等复合后缀）
  即放宽方法名白名单，覆盖企业自研基类与二次封装。

含负样本：方法名/接收者/实参都不像数据访问时不误报。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.dataflow.taint import has_sql_text, is_dao_receiver


# ---------------- 纯函数：SQL 文本信号 ----------------
def test_has_sql_text():
    assert has_sql_text("query('SELECT * FROM orders WHERE id = $1', [id])")
    assert has_sql_text('execute("UPDATE t SET x=1 WHERE id=?", id)')
    assert has_sql_text('raw("DELETE FROM t WHERE id=?", id)')
    assert not has_sql_text("query(id)")           # 无 SQL 文本
    assert not has_sql_text("sendResponse('ok')")  # 非 SQL 字符串


# ---------------- 纯函数：DAO 接收者信号 ----------------
def test_is_dao_receiver_standalone():
    for t in ("db.query", "conn.execute", "cursor.fetchone", "repo.get", "dao.find",
              "mapper.select", "store.read", "model.get", "collection.find"):
        assert is_dao_receiver(t), t


def test_is_dao_receiver_camel_snake_suffix():
    # 企业常见复合名：camelCase / snake_case / PascalCase 后缀
    for t in ("orderRepo.fetch", "user_repo.get", "orderDao.find", "UserRepository.get",
              "orderMapper.select"):
        assert is_dao_receiver(t), t


def test_is_dao_receiver_no_method_name_fp():
    # 方法名里含 model/store 不应误判（getModel/saveToStore 是方法，不是接收者）
    for t in ("getModel", "user.getModel", "saveToStore", "obj.toJSON"):
        assert not is_dao_receiver(t), t


# ---------------- 集成：SQL 文本 sink ----------------
def test_sql_text_sink_detected():
    cands, _ = cli.scan(_REPO / "tests" / "fixtures" / "sink" / "sql_text")
    assert cands, "原生 SQL 文本（node-postgres client.query）应被识别为数据访问候选"


# ---------------- 集成：DAO 接收者 sink ----------------
def test_dao_receiver_sink_detected():
    cands, _ = cli.scan(_REPO / "tests" / "fixtures" / "sink" / "dao_receiver")
    assert cands, "自研 DAO（orderRepo.fetch）应被识别为数据访问候选"


# ---------------- 集成：负样本不误报 ----------------
def test_negative_no_data_access():
    cands, _ = cli.scan(_REPO / "tests" / "fixtures" / "sink" / "negative")
    assert not cands, "方法名/接收者/实参均不像数据访问时不应产出候选"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")
