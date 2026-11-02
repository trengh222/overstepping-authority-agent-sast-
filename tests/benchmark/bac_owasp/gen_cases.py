"""规模扩展生成器：按模板 × 资源域批量生成**标签由构造保证**的越权用例。

用途：人工撰写的用例覆盖面优先，但单点数量有限；本生成器把 A1 的 6 个正/负模板族
（Java/JS/Go 各一对）展开到 6 个资源域，产出 36 个 A1 用例，用于规模压力与「同模板
跨资源域一致性」回归。生成用例的 case_id 以 ``gen-`` 开头，计分器会把它们单独列在
``generated`` 分组，不污染人工用例（authored）的主指标。

语言范围与检测范围一致：Java / JavaScript / Go（Python、PHP 已从项目中移除）。

用法::

    $env:PYTHONPATH = "$PWD/../../../src"
    python gen_cases.py            # 生成 corpus/ 与 fragments/gen.csv
    python gen_cases.py --dry-run  # 只打印计划
    python gen_cases.py --clean    # 先删除已有 gen-* 用例
"""
import argparse
import csv
import shutil
from pathlib import Path

SUITE = Path(__file__).resolve().parent
CORPUS = SUITE / "corpus"
FRAGMENTS = SUITE / "fragments"

RESOURCES = {
    "order": ("Order", "orders"),
    "invoice": ("Invoice", "invoices"),
    "document": ("Document", "documents"),
    "message": ("Message", "messages"),
    "file": ("FileRecord", "files"),
    "ticket": ("Ticket", "tickets"),
}


def java_pos(entity: str, table: str) -> list:
    pkg = "com.bac.gen." + table.replace("-", "_") + "_pos"
    return [
        (f"{entity}Controller.java", f"""package {pkg};

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1：路径参数 id 直接查库并返回，没有任何归属校验。 */
@RestController
@RequestMapping("/api/{table}")
public class {entity}Controller {{

    @Resource
    private {entity}Service {table}Service;

    @GetMapping("/{{id}}")
    public {entity} detail(@PathVariable("id") Long id) {{
        return {table}Service.getById(id);
    }}
}}
"""),
        (f"{entity}Service.java", f"""package {pkg};

/** 无所有权过滤：按主键直接取。 */
public class {entity}Service {{

    public {entity} getById(Long id) {{
        return {entity}Mapper.selectById(id);
    }}
}}
"""),
    ]


def java_neg(entity: str, table: str) -> list:
    pkg = "com.bac.gen." + table.replace("-", "_") + "_neg"
    return [
        (f"{entity}Controller.java", f"""package {pkg};

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

/** A1 负例：查询在 service 层绑定当前登录用户。 */
@RestController
@RequestMapping("/api/{table}")
public class {entity}Controller {{

    @Resource
    private {entity}Service {table}Service;

    @GetMapping("/{{id}}")
    public {entity} detail(@PathVariable("id") Long id) {{
        Long uid = CurrentUser.id();
        return {table}Service.getByIdAndUserId(id, uid);
    }}
}}
"""),
        (f"{entity}Service.java", f"""package {pkg};

/** 归属过滤：id + userId 双条件。 */
public class {entity}Service {{

    public {entity} getByIdAndUserId(Long id, Long userId) {{
        return {entity}Mapper.selectByIdAndUserId(id, userId);
    }}
}}
"""),
    ]


def js_pos(entity: str, table: str) -> list:
    return [("routes.js", f'''// A1：Express 直接按 :id 查库返回，无归属校验。
const express = require("express");
const db = require("../db");

const router = express.Router();

router.get("/api/{table}/:id", async (req, res) => {{
  const row = await db.query("SELECT * FROM {table} WHERE id = ?", [req.params.id]);
  res.json(row);
}});

module.exports = router;
''')]


def js_neg(entity: str, table: str) -> list:
    return [("routes.js", f'''// A1 负例：SQL 同时带 user_id，取会话里的当前用户。
const express = require("express");
const db = require("../db");

const router = express.Router();

router.get("/api/{table}/:id", async (req, res) => {{
  const uid = req.session.userId;
  const row = await db.query(
    "SELECT * FROM {table} WHERE id = ? AND user_id = ?", [req.params.id, uid]
  );
  res.json(row);
}});

module.exports = router;
''')]


def go_pos(entity: str, table: str) -> list:
    return [("main.go", f'''package main

// A1：Gin 路径参数直接查库返回，无归属校验。
import (
    "database/sql"
    "net/http"

    "github.com/gin-gonic/gin"
)

func main() {{
    r := gin.Default()
    r.GET("/api/{table}/:id", func(c *gin.Context) {{
        var row map[string]any
        db, _ := sql.Open("sqlite3", "app.db")
        db.QueryRow("SELECT * FROM {table} WHERE id = ?", c.Param("id")).Scan(&row)
        c.JSON(http.StatusOK, row)
    }})
    r.Run(":8080")
}}
''')]


def go_neg(entity: str, table: str) -> list:
    return [("main.go", f'''package main

// A1 负例：SQL 带 user_id，取认证中间件写入的 uid。
import (
    "database/sql"
    "net/http"

    "github.com/gin-gonic/gin"
)

func main() {{
    r := gin.Default()
    r.GET("/api/{table}/:id", func(c *gin.Context) {{
        uid, _ := c.Get("uid")
        db, _ := sql.Open("sqlite3", "app.db")
        var row map[string]any
        db.QueryRow(
            "SELECT * FROM {table} WHERE id = ? AND user_id = ?", c.Param("id"), uid,
        ).Scan(&row)
        c.JSON(http.StatusOK, row)
    }})
    r.Run(":8080")
}}
''')]


FAMILIES = {
    "java-a1-pos": ("java", "A1-IDOR", 1, java_pos, "路径参数 id 直接查库无归属校验"),
    "java-a1-neg": ("java", "A1-IDOR", 0, java_neg, "service 层 id+userId 归属过滤"),
    "js-a1-pos": ("js", "A1-IDOR", 1, js_pos, "Express :id 直接查库无归属校验"),
    "js-a1-neg": ("js", "A1-IDOR", 0, js_neg, "SQL 带 user_id 归属过滤"),
    "go-a1-pos": ("go", "A1-IDOR", 1, go_pos, "Gin :id 直接查库无归属校验"),
    "go-a1-neg": ("go", "A1-IDOR", 0, go_neg, "SQL 带 user_id 归属过滤"),
}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="批量生成规模压力用例")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--clean", action="store_true", help="先删除已有 gen-* 用例")
    args = ap.parse_args(argv)

    if args.clean:
        removed = 0
        for p in CORPUS.glob("*/gen-*"):
            shutil.rmtree(p, ignore_errors=True)
            removed += 1
        print(f"cleaned {removed} generated cases")

    rows, planned = [], 0
    for family, (lang, cat, real, builder, note) in FAMILIES.items():
        for res, (entity, table) in RESOURCES.items():
            case_id = f"gen-{family}-{res}"
            files = builder(entity, table)
            planned += 1
            primary = files[0][0]
            endpoint = f"/api/{table}/{{id}}" if lang == "java" else f"/api/{table}/:id"
            rows.append({"case_id": case_id, "category": cat, "language": lang,
                         "real_vulnerability": real, "endpoint_path": endpoint,
                         "source_file": f"{lang}/{case_id}/{primary}", "note": note})
            if args.dry_run:
                continue
            case_dir = CORPUS / lang / case_id
            for rel, text in files:
                target = case_dir / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8", newline="\n")
    print(f"planned {planned} generated cases")
    if args.dry_run:
        return 0

    FRAGMENTS.mkdir(parents=True, exist_ok=True)
    with open(FRAGMENTS / "gen.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["case_id", "category", "language", "real_vulnerability",
                                          "endpoint_path", "source_file", "note"])
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {FRAGMENTS / 'gen.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
