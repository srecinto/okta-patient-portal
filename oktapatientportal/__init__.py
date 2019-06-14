import os

from flask import Flask
# from flask_sslify import SSLify

default_settings = {
    "config": {
        "client_id": os.getenv("OKTA_CLIENT_ID", "-Client Id in Okta App-"),
        "issuer": os.getenv("OKTA_ISSUER", None),
        "app_config": os.getenv("SITE_APP_CONFIG", "./well-known/default-settings"),
        "base_url": os.getenv("OKTA_ORG_URL", "-My Okta Org Here-"),
        "redirect_uri": os.getenv("OKTA_OIDC_REDIRECT_URI", "-OIDC Auth Code Endpoint for your app-"),
        "settings": {
            "skin": os.getenv("SITE_SKIN", "blue"),
            "base_title": os.getenv("SITE_BASE_TITLE", "Medical Group"),
            "current_title": "Patient Portal",
            "app_base_url": os.getenv("APP_BASE_URL", "-Default Landing URL for your app-"),
            "app_title": os.getenv("SITE_APP_TITLE", "Patient Portal"),
            "app_logo": os.getenv("SITE_APP_LOGO", "images/logo_{0}.png".format(os.getenv("SITE_SKIN", "blue"))),
            "app_favicon": os.getenv("SITE_APP_FAVICON", "images/favicon.ico"),
            "app_slogan": os.getenv("SITE_APP_SLOGAN", "Get Better Sooner"),
            "app_config": os.getenv("SITE_APP_CONFIG", "./well-known/default-settings")

        }
    }
}

secure_settings = {
    "config": {
        "client_secret": os.getenv("OKTA_CLIENT_SECRET", "-Client Secret in Okta App-"),
        "okta_api_token": os.getenv("OKTA_API_TOKEN", "-Okta API Token-"),
        "app_secret_key": os.getenv("SECRET_KEY", "-A GUID for your secret key-"),
    },
}

app = Flask(__name__)
app.config["SECRET_KEY"] = secure_settings["config"]["app_secret_key"]

# sslify = SSLify(app, permanent=True, subdomains=True)

# This must go last to avoid the circular dependency issue

import oktapatientportal.views
