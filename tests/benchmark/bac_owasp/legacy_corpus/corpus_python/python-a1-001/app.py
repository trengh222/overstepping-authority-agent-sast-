from flask import Flask, abort, jsonify
from flask_login import login_required

from service import OrderService

app = Flask(__name__)
orders = OrderService()


@app.route("/api/orders/<int:order_id>", methods=["GET"])
@login_required
def get_order(order_id):
    order = orders.fetch(order_id)
    if order is None:
        abort(404)
    return jsonify(order)
