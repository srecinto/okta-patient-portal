import base64
import json
import uuid
import os

from oktapatientportal import default_settings

from functools import wraps
from flask import request, session, make_response, redirect, render_template

from utils.rest import RestUtil
from utils.okta import OktaAuth, OktaAdmin

json_headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer {0}".format(os.getenv("UDP_SECRET_KEY", ""))
}


def apply_remote_config(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        print("apply_remote_config()")

        if "is_config_set" not in session:
            session["is_config_set"] = False

        print("session['is_config_set']: {0}".format(session["is_config_set"]))

        # Request from service to get app config, if not is session or cache
        well_known_default_settings_url = None
        if not session["is_config_set"]:
            print("No session set")

            # Assumes the first two components are what we need
            split_domain_parts = get_domain_parts_from_request(request)
            session["udp_subdomain"] = split_domain_parts["udp_subdomain"]
            session["demo_app_name"] = split_domain_parts["demo_app_name"]
            session["remaining_domain"] = split_domain_parts["remaining_domain"]

            # aply default sessting always
            map_config(default_settings, session)

            # look for remote config
            well_known_default_settings_url = get_configs_url(session["udp_subdomain"], session["demo_app_name"])
            print("well_known_default_settings_url: {0}".format(well_known_default_settings_url))

            config_json = RestUtil.execute_get(well_known_default_settings_url, json_headers)
            print("config_json: {0}".format(json.dumps(config_json, indent=4, sort_keys=True)))

            # If invalid response, default to default / environment setting
            if "status" in config_json:
                if config_json["status"] == "ready":
                    print("Remote config success. Mapping config to session")
                    map_config(config_json, session)
                    # print("Session Dump: {0}".format(session))
                    subdomain_config_url = os.getenv("UDP_SUBDOMAIN_URL", "{udp_subdomain}")
                    # print("subdomain_config_url: {0}".format(subdomain_config_url))
                    subdomain_config_url = subdomain_config_url.format(udp_subdomain=session["udp_subdomain"])
                    # print("subdomain_config_url: {0}".format(subdomain_config_url))
                    # print("json_headers: {0}".format(json_headers))
                    subdomain_config_json = RestUtil.execute_get(subdomain_config_url, json_headers)
                    print("subdomain_config_json: {0}".format(json.dumps(subdomain_config_json, indent=4, sort_keys=True)))
                    if "okta_api_token" in subdomain_config_json:
                        session["okta_api_token"] = subdomain_config_json["okta_api_token"]
                        session["okta_org_name"] = subdomain_config_json["okta_org_name"]

                    else:
                        raise Exception("Failed to get the Okta API Key from config")

                else:
                    print("Remote config not ready. Default to the local container env and default config")

                session["is_config_set"] = True
            else:
                print("Failed to load remote config from: {0}".format(well_known_default_settings_url))
                response = make_response(
                    render_template(
                        "error.html",
                    site_config=session,
                    error_message="Subdomain '{0}' is not configured.  Check to make sure it is correct.".format(session["udp_subdomain"])
                    )
                )

                return response

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

    udp_subdomain = os.getenv("UDP_SUB_DOMAIN", udp_subdomain)
    demo_app_name = os.getenv("UDP_APP_NAME", demo_app_name)
    remaining_domain = os.getenv("UDP_BASE_DOMAIN", remaining_domain)

    print("udp_subdomain: {0}".format(udp_subdomain))
    print("demo_app_name: {0}".format(demo_app_name))

    split_domain_parts = {
        "udp_subdomain": udp_subdomain,
        "demo_app_name": demo_app_name,
        "remaining_domain": remaining_domain
    }

    return split_domain_parts


def get_configs_url(udp_subdomain, demo_app_name):
    print("get_well_know_settings_url()")
    config_url = default_settings["app_config"].format(
        udp_subdomain=udp_subdomain,
        demo_app_name=demo_app_name)

    well_known_default_settings_url = "{0}".format(config_url)

    return well_known_default_settings_url


def map_config(config, session):
    print("map_config(config, session)")

    safe_assign_config_item_to_session("client_id", config, session)
    safe_assign_config_item_to_session("client_secret", config, session)
    safe_assign_config_item_to_session("issuer", config, session)
    safe_assign_config_item_to_session("redirect_uri", config, session)
    safe_assign_config_item_to_session("okta_api_token", config, session)
    safe_assign_config_item_to_session("okta_org_name", config, session)

    safe_assign_config_item_to_session("app_base_url", config["settings"], session)
    safe_assign_config_item_to_session("app_favicon", config["settings"], session)
    safe_assign_config_item_to_session("app_logo", config["settings"], session)
    safe_assign_config_item_to_session("app_slogan", config["settings"], session)
    safe_assign_config_item_to_session("app_title", config["settings"], session)
    safe_assign_config_item_to_session("base_title", config["settings"], session)
    safe_assign_config_item_to_session("current_title", config["settings"], session)
    safe_assign_config_item_to_session("skin", config["settings"], session)
    safe_assign_config_item_to_session("spark_post_api_key", config["settings"], session)
    safe_assign_config_item_to_session("spark_post_activate_template_id", config["settings"], session)
    safe_assign_config_item_to_session("login_id_prefix", config["settings"], session)

    # Override the Redirect URI with the environment variable
    session["redirect_uri"] = os.getenv("OKTA_OIDC_REDIRECT_URI", session["redirect_uri"])


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
    curent_application = okta_admin.get_user_application_by_current_client_id(okta_user_id)
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
    print("app: {0}".format(json.dumps(app, indent=4, sort_keys=True)))
    if "profile" in app:
        if ("height" not in app["profile"] and
                "weight" not in app["profile"] and
                app["profile"]["registrationForm"] == "DEFAULT"):
            result = True
        else:
            if "weight" in app["profile"] and "height" in app["profile"]:
                if ((app["profile"]["weight"] == "" or app["profile"]["height"] == "" or
                        app["profile"]["weight"] is None or app["profile"]["height"] is None) and
                        app["profile"]["registrationForm"] == "DEFAULT"):
                    result = True

    return result


def show_user_reg_form_alt1(user, app):
    print("show_user_reg_form_alt1()")
    result = False

    if "profile" in app:
        if ("dob" not in app["profile"] and
                app["profile"]["registrationForm"] == "ALT1"):
            result = True
        else:
            if "dob" in app["profile"]:
                if ((app["profile"]["dob"] == "" or user["profile"]["mobilePhone"] == "" or
                        app["profile"]["dob"] is None or user["profile"]["mobilePhone"] is None) and
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
    okta_admin = OktaAdmin(session)

    #  print("login_form_data: {0}".format(json.dumps(login_form_data, indent=4, sort_keys=True)))
    authn_json_response = okta_auth.authenticate(
        username=session["login_id_prefix"] + user_name,
        password=password,
        headers=request.headers)

    # print("authn_json_response: {0}".format(json.dumps(authn_json_response, indent=4, sort_keys=True)))
    if "sessionToken" in authn_json_response:

        # Added to fix issue where users pre exsist but are not assigned to the patient portal app as a patient
        # Look up if user is in  this app/subdomain
        # TODO: Clean this up to use Terraform setting or Group Rule
        user_id = authn_json_response["_embedded"]["user"]["id"]
        #print("user_id: {0}".format(user_id))
        # Look up Patient group for this app/subdomain
        patient_group_name = "{0}_{1}_patient".format(
            session["udp_subdomain"],
            session["demo_app_name"]
        )
        print("patient_group_name: {0}".format(patient_group_name))
        patient_groups = okta_admin.get_groups_by_name(patient_group_name)
        has_patient_group = False

        if len(patient_groups)  != 0:
            patient_group = okta_admin.get_groups_by_name(patient_group_name)[0]
            #print("patient_group: {0}".format(json.dumps(patient_group, indent=4, sort_keys=True)))

            user_groups = okta_admin.get_user_groups(user_id)
            #print("user_groups: {0}".format(json.dumps(user_groups, indent=4, sort_keys=True)))

            for group in user_groups:
                if patient_group["id"] == group["id"]:
                    has_patient_group = True
                    break

        if not has_patient_group:
            # Assign User to group
            group_assignment_response = okta_admin.assign_user_to_group(patient_group["id"], user_id);
            #print("user_groups: {0}".format(json.dumps(user_groups, indent=4, sort_keys=True)))

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
        auth_response["status"] = "SUCCESS"

        #  print("oauth_authorize_url: {0}".format(oauth_authorize_url))
    elif "errorSummary" in authn_json_response:
        auth_response["errorMessage"] = "Login Unsuccessful: {0}".format(authn_json_response["errorSummary"])
    else:
        # pass the message down for further processing like MFA
        auth_response = authn_json_response

    return auth_response


def safe_assign_config_item_to_session(key, collection, session):
    if key in collection:
        session[key] = collection[key]

def get_factor_name(factorType, provider):
    factor_name = factorType

    if (factorType == "token:software:totp"):
        if (provider == "GOOGLE"):
            factor_name = "Google Authenticator"
    elif (factorType == "push"):
        factor_name = "Okta Verify"
    elif (factorType == "sms"):
        factor_name = "SMS"
    elif (factorType == "call"):
        factor_name = "Voice Call"
    elif (factorType == "question"):
        factor_name = "Security Question"

    return factor_name


def get_oauth_authorize_url(okta_session_token=None):
    print("get_oauth_authorize_url()")
    okta_auth = OktaAuth(session)

    auth_options = {
        "response_mode": "form_post",
        "prompt": "none",
        "scope": "openid profile email"
    }

    if "state" not in session:
        session["state"] = str(uuid.uuid4())

    if okta_session_token:
        auth_options["sessionToken"] = okta_session_token

    oauth_authorize_url = okta_auth.create_oauth_authorize_url(
            response_type="code",
            state=session["state"],
            auth_options=auth_options
        )

    return oauth_authorize_url