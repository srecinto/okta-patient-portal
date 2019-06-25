import os
import json
import uuid

from oktapatientportal import app

from flask import request, session, send_from_directory, redirect, make_response, render_template
from datetime import datetime

from utils.okta import OktaAuth, OktaAdmin
from utils.view import apply_remote_config, handle_invalid_tokens, send_mail
from utils.view import get_claims_from_token, authenticated, get_modal_options


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
    user = None
    modal_options = None

    session["current_title"] = "{0} | {1} Home".format(session["base_title"], session["app_title"])

    # Get user Claims from Id Token for signed in display
    if("token" in request.cookies and "id_token" in request.cookies):
        id_token_claims = get_claims_from_token(request.cookies["id_token"])
        if id_token_claims:
            if "sub" in id_token_claims:
                okta_admin = OktaAdmin(session)
                user = okta_admin.get_user(id_token_claims["sub"])
                modal_options = get_modal_options(id_token_claims["sub"])

    response = make_response(
        render_template(
            "index.html",
            site_config=session,
            user=user,
            modal_options=modal_options
        )
    )

    handle_invalid_tokens(session, response)

    return response


@app.route('/oidc', methods=["POST"])
def oidc():
    """ handler for the oidc call back of the app """
    print("oidc()")
    #  print(request.form)

    if "error" in request.form:
        print("ERROR: {0}, MESSAGE: {1}".format(request.form["error"], request.form["error_description"]))

    # if session["state"] == request.form["state"]:
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
    # else:
        # print("FAILED TO MATCH STATE!!!")
        # response = make_response(redirect("/"))

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

    return json.dumps(auth_response)


@app.route('/login-token/<token>', methods=["POST"])
def login_token(token):
    """ Handle either full form post redirect or a json response with redirect url """
    print("login_token()")
    redirect_url = "/"

    # print("authn_json_response: {0}".format(json.dumps(authn_json_response, indent=4, sort_keys=True)))
    if token:
        okta_auth = OktaAuth(session)
        session["state"] = str(uuid.uuid4())
        redirect_url = okta_auth.create_oauth_authorize_url(
            response_type="code",
            state=session["state"],
            auth_options={
                "response_mode": "form_post",
                "prompt": "none",
                "scope": "openid profile email",
                "sessionToken": token,
            }
        )
        # print("redirect_url: {0}".format(redirect_url))

    return make_response(redirect(redirect_url))


@app.route("/logout", methods=["GET"])
def logout():
    print("logout()")
    app_base_url = request.url_root

    if request.url_root.startswith('http://'):
        app_base_url = request.url_root.replace('http://', 'https://', 1)

    redirect_url = "{host}/login/signout?fromURI={redirect_path}".format(
        host=session["base_url"],
        redirect_path=app_base_url
    )

    print("redirect_url: {0}".format(redirect_url))

    response = make_response(redirect(redirect_url))
    response.set_cookie("token", "")
    response.set_cookie("id_token", "")

    return response


@app.route("/accept-consent", methods=["POST"])
@authenticated
def accept_consent():
    print("accept_consent()")
    concent_accept_response = {
        "success": False
    }

    id_token = request.cookies.get("id_token")
    okta_admin = OktaAdmin(session)

    user_id = get_claims_from_token(id_token)["sub"]
    app = okta_admin.get_user_application_by_current_client_id(user_id)
    app_id = session["client_id"]

    app["profile"]["userConsentDate"] = datetime.today().strftime('%Y-%m-%d')
    app["profile"]["userConsentToS"] = "1.0"

    update_response = okta_admin.update_application_user_profile(app_id, user_id, app)

    if "errorSummary" in update_response:
        concent_accept_response["errorMessage"] = update_response["errorSummary"]
    else:
        concent_accept_response["success"] = True

    return json.dumps(concent_accept_response)


@app.route("/register-basic", methods=["POST"])
def register_basic():
    print("register_basic()")
    login_form_data = request.get_json()

    register_basic_response = {
        "success": False
    }

    okta_admin = OktaAdmin(session)
    patient_group = okta_admin.get_groups_by_name("Patient")[0]  # Default to first found group by name

    user = {
        "profile": {
            "firstName": "NOT_SET",
            "lastName": "NOT_SET",
            "email": login_form_data["username"],
            "login": login_form_data["username"]
        },
        "credentials": {
            "password": {"value": login_form_data["password"]}
        },
        "groupIds": [
            patient_group["id"]
        ]
    }

    created_user = okta_admin.create_user(user)
    # print("created_user: {0}".format(json.dumps(created_user, indent=4, sort_keys=True)))

    if "errorSummary" in created_user:
        register_basic_response["errorMessage"] = created_user["errorSummary"]
        if "errorCauses" in created_user:
            register_basic_response["errorMessages"] = []
            for error_cause in created_user["errorCauses"]:
                register_basic_response["errorMessages"].append({
                    "errorMessage": error_cause["errorSummary"]
                })

    else:
        #  Send activation email
        recipients = [{"address": {"email": created_user["profile"]["email"]}}]
        substitution = {
            "activation_email": created_user["profile"]["email"],
            "activation_key": created_user["id"],
            "udp_subdomain": session["udp_subdomain"],
            "udp_app_name": session["demo_app_name"],
            "domain": session["remaining_domain"],
            "logo_url": session["app_logo"]
        }

        send_mail(
            session["spark_post_activate_template_id"],
            recipients,
            session["spark_post_api_key"],
            substitution)

        register_basic_response["success"] = True

    return json.dumps(register_basic_response)


@app.route("/register-default", methods=["POST"])
@authenticated
def register_default():
    print("register_default()")
    user_form_data = request.get_json()

    register_default_response = {
        "success": False
    }
    id_token = request.cookies.get("id_token")
    user_id = get_claims_from_token(id_token)["sub"]
    okta_admin = OktaAdmin(session)

    user = {
        "profile": {
            "firstName": user_form_data["firstName"],
            "lastName": user_form_data["lastName"],
            "height": user_form_data["height"],
            "weight": user_form_data["weight"]
        }
    }

    updated_user = okta_admin.update_user(user_id, user)
    # print("updated_user: {0}".format(json.dumps(updated_user, indent=4, sort_keys=True)))

    if "errorSummary" in updated_user:
        register_default_response["errorMessage"] = updated_user["errorSummary"]

        if "errorCauses" in updated_user:
            register_default_response["errorMessages"] = []
            for error_cause in updated_user["errorCauses"]:
                register_default_response["errorMessages"].append({
                    "errorMessage": error_cause["errorSummary"]
                })
    else:
        register_default_response["success"] = True
        register_default_response["user"] = updated_user

    return json.dumps(register_default_response)


@app.route("/register-alt1", methods=["POST"])
@authenticated
def register_alt():
    print("register_alt()")
    user_form_data = request.get_json()

    register_alt1_response = {
        "success": False
    }
    id_token = request.cookies.get("id_token")
    user_id = get_claims_from_token(id_token)["sub"]
    okta_admin = OktaAdmin(session)

    user = {
        "profile": {
            "firstName": user_form_data["firstName"],
            "lastName": user_form_data["lastName"],
            "dob": user_form_data["dob"],
            "mobilePhone": user_form_data["mobilePhone"],
        }
    }

    updated_user = okta_admin.update_user(user_id, user)
    # print("updated_user: {0}".format(json.dumps(updated_user, indent=4, sort_keys=True)))

    if "errorSummary" in updated_user:
        register_alt1_response["errorMessage"] = updated_user["errorSummary"]

        if "errorCauses" in updated_user:
            register_alt1_response["errorMessages"] = []
            for error_cause in updated_user["errorCauses"]:
                register_alt1_response["errorMessages"].append({
                    "errorMessage": error_cause["errorSummary"]
                })
    else:
        register_alt1_response["success"] = True
        register_alt1_response["user"] = updated_user

    return json.dumps(register_alt1_response)


@app.route("/activate/<user_id>", methods=["GET"])
def activate(user_id):
    print("activate(user_id)")

    auth_response = make_response(redirect("/"))

    okta_admin = OktaAdmin(session)
    activation_response = okta_admin.activate_user(user_id, send_email=False)
    print("activation_response: {0}".format(json.dumps(activation_response, indent=4, sort_keys=True)))

    if "activationToken" in activation_response:
        okta_auth = OktaAuth(session)
        auth_response = okta_auth.authenticate_with_activation_token(activation_response["activationToken"])
        # print("auth_response: {0}".format(json.dumps(auth_response, indent=4, sort_keys=True)))
        if "sessionToken" in auth_response:
            auth_response = login_token(auth_response["sessionToken"])

    return auth_response


@app.route("/test")
@authenticated
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
