#!/usr/bin/python3
from flask import Flask, redirect, url_for, request, render_template
from datetime import datetime
import time
import sqlite3
from flask import g, session, flash

import os

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

if __name__ == "__main__":
    app.run(debug=True)
