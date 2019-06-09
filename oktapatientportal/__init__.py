import os

from flask import Flask
from flask_sslify import SSLify

default_settings = {
    "site_config": {
        "skin": os.getenv("SITE_SKIN", "blue"),
        "base_title": os.getenv("SITE_BASE_TITLE", "Medical Group"),
        "current_title": "Patient Portal",
        "app_title": os.getenv("SITE_APP_TITLE", "Patient Portal"),
        "app_logo": os.getenv("SITE_APP_LOGO", "images/logo_{0}.png".format(os.getenv("SITE_SKIN", "blue"))),
        "app_favicon": os.getenv("SITE_APP_FAVICON", "images/favicon.ico"),
        "app_slogan": os.getenv("SITE_APP_SLOGAN", "Get Better Sooner"),
    },
    "okta_config": {
        "org_url": os.getenv("OKTA_ORG_URL", "-My Okta Org Here-"),
        "client_id": os.getenv("OKTA_CLIENT_ID", "-Client Id in Okta App-"),
        "redirect_uri": os.getenv("OKTA_OIDC_REDIRECT_URI", "-OIDC Auth Code Endpoint for your app-"),
        "app_base_url": os.getenv("APP_BASE_URL", "-Default Landing URL for your app-"),
        "auth_server_id": os.getenv("OKTA_AUTH_SERVER_ID", None)
    }
}

secure_settings = {
    "okta_config": {
        "client_secret": os.getenv("OKTA_CLIENT_SECRET", "-Client Secret in Okta App-"),
    },
    "site_config": {
        "app_secret_key": os.getenv("SECRET_KEY", "-A GUID for your secret key-")
    },
}

app = Flask(__name__)
app.config["SECRET_KEY"] = secure_settings["site_config"]["app_secret_key"]

sslify = SSLify(app, permanent=True, subdomains=True)

# This must go last to avoid the circular dependency issue

import oktapatientportal.views