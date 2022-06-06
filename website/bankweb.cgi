#!/usr/bin/python
from wsgiref.handlers import CGIHandler
from bankweb import app

CGIHandler().run(app)
