from flask import Flask, jsonify, session

app = Flask(__name__)
app.secret_key = "benchmark-secret"


@app.before_request
def require_login():
    if not session.get("user_id"):
        return jsonify({"error": "authentication required"}), 401


@app.route("/api/connections", methods=["GET"])
def list_connections():
    return jsonify({
        "user_id": session["user_id"],
        "connections": [{"id": 3, "provider": "github"}],
    })
