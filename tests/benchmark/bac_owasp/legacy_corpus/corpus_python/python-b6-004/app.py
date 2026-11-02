from flask import Flask, jsonify
from flask_login import current_user, login_required

app = Flask(__name__)


def mask_email(value):
    local, _, domain = value.partition("@")
    return f"{local[:1]}***@{domain}"


@app.route("/api/profile", methods=["GET"])
@login_required
def profile():
    return jsonify({
        "id": current_user.id,
        "email": mask_email(current_user.email),
        "phone_last4": current_user.phone[-4:],
    })
