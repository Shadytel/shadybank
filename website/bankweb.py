#!/usr/bin/python3
from flask import Flask, redirect, url_for, request, render_template
from datetime import datetime
import time
import sqlite3
from flask import g, session, flash
from flask_login import LoginManager

import os

login_manager = LoginManager()
datadir = "/Users/astrid/code/shadybucks/srv"
app = Flask(__name__)
app.secret_key = "bb5ba686-0fc9-4b58-bd2a-30b8a28400f7"
from jinja2 import Environment, PackageLoader
env = Environment(loader=PackageLoader("bankweb", "templates"))

@app.before_request
def setup_request():
    g.db = sqlite3.connect("%s/data/db.sqlite3" % (datadir,))

    g.user = None

@app.route("/")
def root():
    template = env.get_template("frontpage-logged-out.html")
    return template.render(data= {}, session= None)

@app.route("/login", methods=["POST"])
def login():
    req_uid = None
    stripe = request.form.get('magstripe')
    pan = request.form.get('pan')
    if (stripe != ''):
        req_uid = lookup_magstripe(stripe)
    else:
        req_uid = lookup_pan(pan)
    return None

@app.route("/history", methods=["GET"])
def history():
    # todo: everything security...
    pan = request.args.get("pan")
    c = g.db.cursor()
    c.execute("select pan, tr_uuid, amount, timestamp, note from transfer where pan = ? order by timestamp asc;",
              (pan,))
    transactions = []
    balance = 0
    for row in c:
        tr = {}
        (pan, tr_uuid, amount, timestamp, note,) = row
        tr["timestamp_human"] = timestamp
        tr["amount"] = amount
        tr["counterparty"] = tr_uuid
        tr["note"] = note
        balance += amount
        tr["balance"] = balance
        transactions.append(tr)
    data = {}
    data["transactions"] = transactions
    template = env.get_template("transaction-history.html")
    return template.render(data= data, session = {})

def lookup_pan(pan):
    c = g.db.cursor()
    c.execute("select pan from account where pan = ? limit 1;", (pan,))
    user = c.fetchone()[0]
    if user is not None:
        g.user = user

# call this function whenever we get a swipe.  returns the user-id if
# it's valid stripe data.
def lookup_magstripe(trackdata):
    return None

# %TRACK1? ;TRACK2?
def split_magstripe(stripe):
    match = re.match(r'%(.*)\?.*;(.*)\?', stripe)
    track1 = match.group(1)
    track2 = match.group(2)
    return (track1, track2, )

# if we have business logic to do with stripe data, such as noting if
# the stripe has been altered, it should go here.  shadybank is not
# yet smart enough however.
def run_stripe(track1, track2):
    c = g.db.cursor()
    c.execute("select pan from account where track1 = ? and track2 = ? limit 1;",
              (track1, track2, ))
    user = c.fetchone()[0]
    return user

if __name__ == "__main__":
    app.run(debug=True)
