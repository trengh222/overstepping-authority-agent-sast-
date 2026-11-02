import sqlite3


class ReportService:
    def fetch(self, report_id):
        conn = sqlite3.connect("app.db")
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT id, owner_id, title, body FROM reports WHERE id = ?",
                (report_id,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()
