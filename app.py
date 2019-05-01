import os
import json

from functools import wraps
from flask import Flask, request, send_from_directory, redirect, make_response, render_template

"""
GLOBAL VARIABLES ########################################################################################################
"""
app = Flask(__name__)
app.config.update({
    "SECRET_KEY": "6w_#w*~AVts3!*yd&C]jP0(x_1ssd]MVgzfAw8%fF+c@|ih0s1H&yZQC&-u~O[--"  # For the session
    })

page_config = { }


"""
UTILS ###################################################################################################################
"""


"""
ROUTES ##################################################################################################################
"""


@app.route('/<path:filename>')
def serve_static_html(filename):
    """ serve_static_html() generic route function to serve files in the 'static' folder """
    # print("serve_static_html('{0}')".format(filename))
    root_dir = os.path.dirname(os.path.realpath(__file__))
    return send_from_directory(os.path.join(root_dir, 'static'), filename)


@app.route('/')
def index():
    """ handler for the root url path of the app """
    print("index()")

    site_config["current_title"] = "{0} | {1} Home".format(
        site_config["base_title"],
        site_config["app_title"])

    response = make_response(
        render_template(
            "index.html",
            site_config=site_config
        )
    )

    return response


"""
MAIN ##################################################################################################################
"""
if __name__ == "__main__":
    # This is to run on c9.io.. you may need to change or make your own runner
    
    site_config = {
        "skin": os.getenv("SITE_SKIN", "blue"),
        "base_title": os.getenv("SITE_BASE_TITLE", "Medical Group"),
        "current_title": "",
        "app_title": os.getenv("SITE_APP_TITLE", "Patient Portal"),
        "app_logo": os.getenv("SITE_APP_LOGO", "images/logo_{0}.png".format(
            os.getenv("SITE_SKIN", "blue"))),
        "app_favicon": os.getenv("SITE_APP_FAVICON", "images/favicon.ico"),
        "app_slogan": os.getenv("SITE_APP_SLOGAN", "Get Better Sooner"),
    }
    
    print("site_config: {0}".format(json.dumps(site_config, indent=4, sort_keys=True)))
    
    app.run(host=os.getenv("IP", "0.0.0.0"), port=int(os.getenv("PORT", 8080)))