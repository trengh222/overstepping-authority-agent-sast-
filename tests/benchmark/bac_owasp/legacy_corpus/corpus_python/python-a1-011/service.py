import sqlite3


class InvoiceService:
    def get_for_user(self, invoice_id, user_id):
        conn = sqlite3.connect("app.db")
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT id, user_id, total, status FROM invoices "
                "WHERE id = ? AND user_id = ?",
                (invoice_id, user_id),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()
