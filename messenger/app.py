"""Local demo relay with volatile mailboxes and public recipient labels."""

import base64
from collections import deque

from flask import Flask, abort, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
mailbox = deque(maxlen=100)


@app.post("/inbox/<recipient>")
def send_message(recipient):
    envelope = request.get_json(silent=True)
    if not isinstance(envelope, dict) or set(envelope) != {"wrapped_key", "token"}:
        abort(400)
    try:
        if not all(base64.b64decode(value, validate=True) for value in envelope.values()):
            abort(400)
    except (TypeError, ValueError):
        abort(400)
    mailbox.append((recipient, envelope))
    return "", 201


@app.get("/inbox/<recipient>")
def read_inbox(recipient):
    return [envelope for address, envelope in list(mailbox) if address == recipient]
