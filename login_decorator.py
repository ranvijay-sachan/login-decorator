import os
import requests
import json
from functools import wraps
from flask import Flask, request, jsonify, Response

app = Flask(__name__)


# Format error response and append status code.
def handle_error(error, status_code):
    resp = jsonify(error)
    resp.status_code = status_code
    return resp


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', None)
        if not auth:
            return handle_error(
                {'code': 'authorization_header_missing', 'description': 'Authorization header is expected'}, 401)

        parts = auth.split()

        if parts[0].lower() != 'bearer':
            return handle_error(
                {'code': 'invalid_header', 'description': 'Authorization header must start with Bearer'}, 401)
        elif len(parts) == 1:
            return handle_error({'code': 'invalid_header', 'description': 'Token not found'}, 401)
        elif len(parts) > 2:
            return handle_error(
                {'code': 'invalid_header', 'description': 'Authorization header must be Bearer + \s + token'}, 401)

        token = parts[1]
        try:
            url = 'http://127.0.0.1:8080/check/token'
            payload = {'token': token}
            headers = {'Content-Type': 'application/json'}
            r = requests.post(url, data=json.dumps(payload), headers=headers)
            print "respomse", r, r.status_code
        except requests.exceptions.RequestException as e:
            return "Error: {}".format(e)
        if r.status_code != 200:
            print "check status code", r.status_code
            return Response('', status=400, mimetype='application/json')
        return f(*args, **kwargs)

    return decorated


# Controllers API

@app.route("/secured/ping")
@requires_auth
def secured_ping():
    return "All good. You only get this message if you're authenticated"


# run it on different post
@app.route("/check/token", methods=["POST"])
def validate_token():
    tokens = ['12345', 'Bearer 1234567']
    if request.json['token'] in tokens:
        return Response('', status=200, mimetype='application/json')
    return Response('', status=400, mimetype='application/json')


if __name__ == "__main__":
    app.run()
