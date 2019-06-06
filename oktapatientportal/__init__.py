import os

from flask import Flask
from flask_sslify import SSLify

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "<A GUID for your secret key>")

sslify = SSLify(app, permanent=True, subdomains=True)

import oktapatientportal.views
