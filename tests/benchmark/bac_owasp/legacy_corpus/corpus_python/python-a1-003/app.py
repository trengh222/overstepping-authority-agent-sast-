from flask import Flask, jsonify, request
from flask_login import login_required

from service import DocumentService

app = Flask(__name__)
documents = DocumentService()


@app.route("/api/documents/share", methods=["POST"])
@login_required
def share_document():
    payload = request.json or {}
    document_id = payload.get("document_id")
    if document_id is None:
        return jsonify({"error": "document_id is required"}), 400
    document = documents.get(document_id)
    if document is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(document)
