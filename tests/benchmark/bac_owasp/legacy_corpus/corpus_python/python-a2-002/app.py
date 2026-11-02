from flask import Flask, jsonify

from config_service import read_config
from middleware import role_required

app = Flask(__name__)


@app.route("/api/admin/config", methods=["GET"])
@role_required("admin")
def admin_config():
    return jsonify(read_config())
