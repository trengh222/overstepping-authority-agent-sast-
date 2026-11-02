import os

from flask import Flask, abort, request, send_file
from flask_login import login_required

app = Flask(__name__)

FILES = {
    11: {"owner_id": 7, "path": "reports/q3.pdf"},
    12: {"owner_id": 8, "path": "invoices/1001.pdf"},
}


@app.route("/api/files/<int:file_id>", methods=["GET"])
@login_required
def download_file(file_id):
    record = FILES.get(file_id)
    if record is None:
        abort(404)
    claimed_owner = request.args.get("owner_id", type=int)
    if claimed_owner != record["owner_id"]:
        abort(403)
    return send_file(os.path.join("storage", record["path"]))
