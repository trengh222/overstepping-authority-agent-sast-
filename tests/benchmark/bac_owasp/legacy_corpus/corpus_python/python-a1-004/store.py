MESSAGES = [
    {"id": 1, "to_user": 7, "body": "hello"},
    {"id": 2, "to_user": 8, "body": "private"},
]


def list_messages(user_id):
    return [item for item in MESSAGES if item["to_user"] == user_id]
