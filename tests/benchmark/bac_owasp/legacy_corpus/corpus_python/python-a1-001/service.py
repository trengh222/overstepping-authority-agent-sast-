from repository import find_order


class OrderService:
    def fetch(self, order_id):
        row = find_order(order_id)
        if row is None:
            return None
        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "status": row["status"],
            "total": row["total"],
        }
