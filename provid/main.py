#!/usr/bin/env python
# -*- encoding: utf-8 -*
# vim: ft=python ff=unix fenc=utf-8
# file: main.py

import json
import flask
app = flask.Flask(__name__)

def R(ok, msg = None):
    r = {}
    r["op"] = bool(ok)
    if msg:
        r["msg"] = msg
    else:
        r["msg"] = ''
    if not r["op"]:
        return (json.dumps(r), 400)
    return (json.dumps(r), 200)

@app.route('/')
def _():
    return R(0, "unknown operation")

def props(op, jpop):
    pass

def op_update(op, jdat):
    pass

def op_block(op, jdat):
    pass

def op_create(op, jdat):
    if op == "create":
        if "secret" not in jdat:
            return R(False, "new user without password?")
        pass
    elif op == "remove":
        pass
    return R(True)

ops = {
        "update": op_update,
        "block": op_block,
        "unblock": op_block,
        "create": op_create,
        "remove": op_create
        }

@app.route('/op', methods = ["POST"])
def op():
    # нужно заменить на что-то нормальное.
    data = flask.request.form.keys()[0]
    jdata = None
    # -
    try:
        jdata = json.loads(data)
    except ValueError as e:
        return R(False, e.message)

    if type(jdata) != dict:
        return R(False, "not be a dictable")

    # совсем обязательные поля для всех сообщений
    for x in ("username", "op"):
        if not x in jdata:
            return R(False, "field '%s' not present" %x)
    
    if jdata["op"] not in ops:
        return R(False, "operation '%s' is impossible" %jdata["op"])

    return ops[jdata["op"]](jdata["op"], jdata)


if __name__ == '__main__':
    app.run(debug = True)

