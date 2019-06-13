import os
import json
import uuid
import requests


from oktapatientportal import app, default_settings, secure_settings

from functools import wraps

from flask import request, session, send_from_directory, redirect, make_response, render_template

from utils.okta import OktaAuth
from utils.rest import RestUtil

json_headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}


def apply_remote_config(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        print("apply_remote_config()")

        if "is_config_set" not in session:
            session["is_config_set"] = False

        print("session['is_config_set']: {0}".format(session["is_config_set"]))

        # Request from service to get app config, if not is session or cache
        if not session["is_config_set"]:
            print("No session set")

            # Assumes the first two components are what we need
            udp_subdomain, demo_app_name = get_domain_parts_from_request(request)
            session["udp_subdomain"] = udp_subdomain
            session["demo_app_name"] = demo_app_name

            well_known_default_settings_url, secrets_url = get_configs_url(udp_subdomain, demo_app_name)
            # print("well_known_default_settings_url: {0}".format(well_known_default_settings_url))

            config_json = RestUtil.execute_get(well_known_default_settings_url, {}, json_headers)
            print("config_json: {0}".format(json.dumps(config_json, indent=4, sort_keys=True)))
            # If invalid response, default to default / environment setting
            if "config" in config_json:
                if config_json["config"]["status"] == "ready":
                    print("Remote config success. Mapping config to session")
                    map_config(config_json["config"], session)

                    print("Getting Secrets config")
                    # print("secrets_url: {0}".format(secrets_url))
                    map_secrets_config(requests.get(secrets_url), session)

                else:
                    print("Remote config not ready. Default to the local container env and default config")
                    set_default_env_secrets(session)

            else:
                print("Remote config failed. Default to the local container env and default config")
                set_default_env_secrets(session)

            session["is_config_set"] = True

        return f(*args, **kws)
    return decorated_function


def get_domain_parts_from_request(request):
    print("get_domain_parts_from_request(request)")

    domain_parts = request.host.split(".")
    udp_subdomain = domain_parts[0]
    demo_app_name = domain_parts[1]

    print("udp_subdomain: {0}".format(udp_subdomain))
    print("demo_app_name: {0}".format(demo_app_name))

    return udp_subdomain, demo_app_name


def set_default_env_secrets(session):
    print("set_default_env_secrets(session)")
    map_config(default_settings["config"], session)

    session["CLIENT_SECRET"] = secure_settings["config"]["client_secret"]
    session["OKTA_API_TOKEN"] = secure_settings["config"]["okta_api_token"]


def get_configs_url(udp_subdomain, demo_app_name):
    print("get_well_know_settings_url()")
    config_url = default_settings["config"]["app_config"].format(
        udp_subdomain=udp_subdomain,
        demo_app_name=demo_app_name)

    well_known_default_settings_url = "{0}".format(config_url)
    secrets_url = "{0}/secret".format(config_url)

    return well_known_default_settings_url, secrets_url


def map_config(config, session):
    print("map_config(config, session)")

    session["client_id"] = config["client_id"]
    session["issuer"] = config["issuer"]
    session["base_url"] = config["base_url"]
    session["redirect_uri"] = config["redirect_uri"]

    session["app_base_url"] = config["settings"]["app_base_url"]
    session["app_favicon"] = config["settings"]["app_favicon"]
    session["app_logo"] = config["settings"]["app_logo"]
    session["app_slogan"] = config["settings"]["app_slogan"]
    session["app_title"] = config["settings"]["app_title"]
    session["base_title"] = config["settings"]["base_title"]
    session["current_title"] = config["settings"]["current_title"]
    session["skin"] = config["settings"]["skin"]


def map_secrets_config(config, session):
    print("map_secrets_config(config, session)")
    try:
        secret_data = config.content.decode('utf-8').splitlines()
        # print("config: {0}".format(config))

        for config_item in secret_data:
            split_config_item = config_item.split("=")
            if len(split_config_item) == 2:
                env_key = split_config_item[0]
                env_value = split_config_item[1]

                session[env_key] = env_value
    except Exception as ex:
        print("Failed to map secrets, setting defaults instead.  Exception: {0}".format(ex))
        set_default_env_secrets(session)


@app.route('/<path:filename>')
def serve_static_html(filename):
    """ serve_static_html() generic route function to serve files in the 'static' folder """
    # print("serve_static_html('{0}')".format(filename))
    root_dir = os.path.dirname(os.path.realpath(__file__))
    return send_from_directory(os.path.join(root_dir, 'static'), filename)


@app.route('/')
@apply_remote_config
def index():
    """ handler for the root url path of the app """
    print("index()")

    session["current_title"] = "{0} | {1} Home".format(session["base_title"], session["app_title"])

    print("skin: {0}".format(session["skin"]))
    response = make_response(
        render_template(
            "index.html",
            site_config=session
        )
    )

    return response


@app.route('/oidc', methods=["POST"])
def oidc():
    """ handler for the oidc call back of the app """
    print("oidc()")
    #  print(request.form)

    if "error" in request.form:
        print("ERROR: {0}, MESSAGE: {1}".format(request.form["error"], request.form["error_description"]))

    if session["state"] == request.form["state"]:
        oidc_code = request.form["code"]
        #  print("oidc_code: {0}".format(oidc_code))
        okta_auth = OktaAuth(session)
        oauth_token = okta_auth.get_oauth_token(
            code=oidc_code,
            grant_type="authorization_code",
            auth_options={
                "client_id": session["client_id"],
                "client_secret": session["CLIENT_SECRET"],
            }
        )
        #  print("oauth_token: {0}".format(json.dumps(oauth_token, indent=4, sort_keys=True)))
        app_landing_page_url = session["app_base_url"]
        response = make_response(redirect(app_landing_page_url))
        response.set_cookie('token', oauth_token["access_token"])
        response.set_cookie('id_token', oauth_token["id_token"])
    else:
        print("FAILED TO MATCH STATE!!!")
        response = make_response(redirect("/"))

    session.pop("state", None)

    return response


@app.route('/login', methods=["POST"])
def login():
    """ Handle either full form post redirect or a json response with redirect url """
    print("login()")
    auth_response = {"success": False}
    login_form_data = request.get_json()
    okta_auth = OktaAuth(session)

    #  print("login_form_data: {0}".format(json.dumps(login_form_data, indent=4, sort_keys=True)))
    authn_json_response = okta_auth.authenticate(
        username=login_form_data["username"],
        password=login_form_data["password"],
        headers=request.headers)

    # print("authn_json_response: {0}".format(json.dumps(authn_json_response, indent=4, sort_keys=True)))
    if "sessionToken" in authn_json_response:
        session["state"] = str(uuid.uuid4())
        oauth_authorize_url = okta_auth.create_oauth_authorize_url(
            response_type="code",
            state=session["state"],
            auth_options={
                "response_mode": "form_post",
                "prompt": "none",
                "scope": "openid",
                "sessionToken": authn_json_response["sessionToken"],
            }
        )

        auth_response["redirectUrl"] = oauth_authorize_url
        auth_response["success"] = True

        # print("oauth_authorize_url: {0}".format(oauth_authorize_url))
    elif "errorSummary" in authn_json_response:
        auth_response["errorMessage"] = "Login Unsuccessful: {0}".format(authn_json_response["errorSummary"])
    else:
        # pass the message down for further processing like MFA
        auth_response = authn_json_response

    return json.dumps(auth_response)


@app.route("/logout", methods=["GET"])
def logout():
    print("logout()")

    redirect_url = "{host}/login/signout?fromURI={redirect_path}".format(
        host=session["base_url"],
        redirect_path=session["app_base_url"]
    )

    print("redirect_url: {0}".format(redirect_url))

    response = make_response(redirect(redirect_url))
    response.set_cookie("token", "")
    response.set_cookie("id_token", "")

    return response


@app.route("/test")
def test():
    print("test()")

    if("token" in request.cookies):
        okta_auth = OktaAuth(session)
        introspection_results_json = okta_auth.introspect(
            token=request.cookies.get("token"),
            headers=request.headers
        )
        print("introspection_results_json: {0}".format(json.dumps(introspection_results_json, indent=4, sort_keys=True)))

        if "active" in introspection_results_json:
            if introspection_results_json["active"]:
                print("Token is Valid")
            else:
                print("Token is Invalid")
        else:
            print("Token is Invalid")

    return "TEST"


@app.route("/clear_session")
def clear_session():
    print("clear_session()")

    session.clear()
    session["is_config_set"] = False

    return make_response(redirect("/"))
