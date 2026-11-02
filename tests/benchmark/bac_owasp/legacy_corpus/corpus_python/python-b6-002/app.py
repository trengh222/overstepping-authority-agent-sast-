from dataclasses import asdict, dataclass

from flask import Flask, jsonify
from flask_login import current_user, login_required

app = Flask(__name__)


@dataclass
class Account:
    id: int
    email: str
    phone: str
    password_hash: str
    api_token: str


@app.route("/api/account", methods=["GET"])
@login_required
def account():
    record = Account(
        id=current_user.id,
        email=current_user.email,
        phone=current_user.phone,
        password_hash=current_user.password_hash,
        api_token=current_user.api_token,
    )
    return jsonify(asdict(record))
