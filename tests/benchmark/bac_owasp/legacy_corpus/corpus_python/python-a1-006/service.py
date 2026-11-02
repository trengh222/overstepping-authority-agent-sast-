import sqlite3


class TicketService:
    def close_many(self, ticket_ids):
        if not ticket_ids:
            return 0
        marks = ",".join("?" for _ in ticket_ids)
        conn = sqlite3.connect("app.db")
        try:
            cursor = conn.execute(
                f"UPDATE tickets SET status = 'closed' WHERE id IN ({marks})",
                ticket_ids,
            )
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()
