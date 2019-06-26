import base64
import json
import requests
import uuid

from oktapatientportal import default_settings, secure_settings

from functools import wraps
from flask import request, session, make_response, redirect

from utils.rest import RestUtil
from utils.okta import OktaAuth, OktaAdmin

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
            split_domain_parts = get_domain_parts_from_request(request)
            session["udp_subdomain"] = split_domain_parts["udp_subdomain"]
            session["demo_app_name"] = split_domain_parts["demo_app_name"]
            session["remaining_domain"] = split_domain_parts["remaining_domain"]

            well_known_default_settings_url, secrets_url = get_configs_url(session["udp_subdomain"], session["demo_app_name"])
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

            print("Session Dump: {0}".format(session))

        return f(*args, **kws)
    return decorated_function


def authenticated(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        print("authenticated()")

        # Just validate they have a legit token.  Any additional access rules will be by another wrapper
        token = request.cookies.get("token")
        if is_token_valid_remote(token, session):
            return f(*args, **kws)
        else:
            print("Access Denied")
            return make_response(redirect("/"))

    return decorated_function


def get_domain_parts_from_request(request):
    print("get_domain_parts_from_request(request)")

    domain_parts = request.host.split(".")
    udp_subdomain = domain_parts[0]
    demo_app_name = domain_parts[1]
    remaining_domain = ".".join(domain_parts[2:])

    print("udp_subdomain: {0}".format(udp_subdomain))
    print("demo_app_name: {0}".format(demo_app_name))

    split_domain_parts = {
        "udp_subdomain": udp_subdomain,
        "demo_app_name": demo_app_name,
        "remaining_domain": remaining_domain
    }

    return split_domain_parts


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
    session["spark_post_api_key"] = config["settings"]["spark_post_api_key"]
    session["spark_post_activate_template_id"] = config["settings"]["spark_post_activate_template_id"]

    if "login_id_prefix" in config["settings"]:
        session["login_id_prefix"] = config["settings"]["login_id_prefix"]
    else:
        session["login_id_prefix"] = ""


def map_secrets_config(config, session):
    print("map_secrets_config(config, session)")
    try:
        secret_data = config.content.decode('utf-8').splitlines()
        print("config: {0}".format(config))

        for config_item in secret_data:
            split_config_item = config_item.split("=")
            if len(split_config_item) == 2:
                env_key = split_config_item[0]
                env_value = split_config_item[1]

                session[env_key] = env_value
    except Exception as ex:
        print("Failed to map secrets, setting defaults instead.  Exception: {0}".format(ex))
        set_default_env_secrets(session)


def is_token_valid_remote(token, session):
        print("is_token_valid_remote(token)")
        result = False

        okta_auth = OktaAuth(session)
        instrospect_response = okta_auth.introspect(token=token)
        # print("instrospect_response: {0}".format(instrospect_response))

        if "active" in instrospect_response:
            result = instrospect_response["active"]

        return result


def handle_invalid_tokens(session, response):
    print("handle_invalid_tokens()")

    can_slear_token = True

    if("token" in request.cookies and "id_token" in request.cookies):
        token = request.cookies["token"]

        if token:
            if is_token_valid_remote(token, session):
                can_slear_token = False  # don't clear tokens, they are valid

        if can_slear_token:
            response.set_cookie("token", "")
            response.set_cookie("id_token", "")


def get_claims_from_token(token):
    print("get_claims_from_token(token)")
    claims = None

    if token:
        jwt = token.encode("utf-8")

        token_payload = jwt.decode().split(".")[1]

        claims_string = decode_base64(token_payload)

        claims = json.loads(claims_string)

    return claims


def decode_base64(data):
    missing_padding = len(data) % 4
    if missing_padding > 0:
        data += "=" * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)


def get_modal_options(okta_user_id):
    print("get_modal_options(okta_user_id)")
    # print("okta_user_id: {0}".format(okta_user_id))
    okta_admin = OktaAdmin(session)
    user = okta_admin.get_user(okta_user_id)
    # print("user: {0}".format(json.dumps(user, indent=4, sort_keys=True)))
    curent_application = okta_admin.get_user_application_by_current_client_id(user["id"])
    # print("curent_application: {0}".format(json.dumps(curent_application, indent=4, sort_keys=True)))
    # print("user: {0}".format(json.dumps(user, indent=4, sort_keys=True)))
    #  Apply Rules based on user and app combo

    modal_options = {
        "showConsent": show_user_consent(curent_application),
        "showRegistrationDefault": show_user_reg_form_default(user, curent_application),
        "showRegistrationAlt1": show_user_reg_form_alt1(user, curent_application)
    }

    return modal_options


def show_user_consent(app):
    print("show_user_consent()")
    result = True
    if "profile" in app:
        if app["profile"]["userConsentDate"] and app["profile"]["userConsentToS"]:
                result = False

    return result


def show_user_reg_form_default(user, app):
    print("show_user_reg_form_default()")
    result = False

    if ("height" not in user["profile"] and
            "weight" not in user["profile"] and
            app["profile"]["registrationForm"] == "DEFAULT"):
        result = True
    else:
        if "dob" in user["weight"] and "dob" in user["height"]:
            if ((user["profile"]["weight"] == "" or user["profile"]["height"] == "") and
                app["profile"]["registrationForm"] == "DEFAULT"):
                result = True

    return result


def show_user_reg_form_alt1(user, app):
    print("show_user_reg_form_alt1()")
    result = False

    if ("dob" not in user["profile"] and
            app["profile"]["registrationForm"] == "ALT1"):
        result = True
    else:
        if "dob" in user["profile"]:
            if ((user["profile"]["dob"] == "" or user["profile"]["mobilePhone"] == "") and
                app["profile"]["registrationForm"] == "ALT1"):
                result = True

    return result


def send_mail(template_id, recipients, spark_post_api_key, substitution=None):
    print("send_mail()")
    url = "https://api.sparkpost.com/api/v1/transmissions"
    headers = {
        "Authorization": spark_post_api_key,
        "Content-Type": "application/json"
    }
    body = {
        "options": {
            "sandbox": False
        },
        "content": {
            "template_id": template_id,
            "use_draft_template": False
        },
        "recipients": recipients
    }

    if substitution:
        body["substitution_data"] = substitution

    return RestUtil.execute_post(url, body, headers=headers)


def create_login_response(user_name, password, session):
    print("create_login_response()")
    auth_response = {"success": False}
    okta_auth = OktaAuth(session)

    #  print("login_form_data: {0}".format(json.dumps(login_form_data, indent=4, sort_keys=True)))
    authn_json_response = okta_auth.authenticate(
        username=session["login_id_prefix"] + user_name,
        password=password,
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
                "scope": "openid profile email",
                "sessionToken": authn_json_response["sessionToken"],
            }
        )

        auth_response["redirectUrl"] = oauth_authorize_url
        auth_response["success"] = True

        #  print("oauth_authorize_url: {0}".format(oauth_authorize_url))
    elif "errorSummary" in authn_json_response:
        auth_response["errorMessage"] = "Login Unsuccessful: {0}".format(authn_json_response["errorSummary"])
    else:
        # pass the message down for further processing like MFA
        auth_response = authn_json_response

    return auth_response
