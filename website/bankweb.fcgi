#!/usr/bin/python
from bankweb import app as application
from werkzeug.contrib.fixers import LighttpdCGIRootFix
# sudo pip3 install flup-py3
from flup.server.fcgi import WSGIServer



if __name__ == "__main__":
    #application.wsgi_app = LighttpdCGIRootFix(application.wsgi_app)
    WSGIServer(application, bindAddress="/tmp/bankweb-fcgi.sock-0").run()
