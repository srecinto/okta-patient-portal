import os
import json
import csv
import uuid

from oktapatientportal import app

from flask import request, session, send_from_directory, redirect, make_response, render_template
from datetime import datetime

from utils.okta import OktaAuth, OktaAdmin
from utils.view import apply_remote_config, handle_invalid_tokens, send_mail, create_login_response
from utils.view import get_claims_from_token, authenticated, get_modal_options, get_factor_name
from utils.view import get_oauth_authorize_url


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
    state_token = request.args.get("stateToken")
    show_mfa_enroll = request.args.get("showMFAEnroll")
    show_bdv = request.args.get("showBDV")
    getNewTokenUrl = ""

    #print("state_token: {0}".format(state_token))
    #print("show_mfa_enroll: {0}".format(state_token))
    #print("show_bdv: {0}".format(state_token))

    session["current_title"] = "{0} | {1} Home".format(session["base_title"], session["app_title"])

    if(state_token):
        print("User needs to set credentials and prove who they are")
        okta_auth = OktaAuth(session)
        token_state = okta_auth.get_transaction_state(state_token)
        print("token_state: {0}".format(json.dumps(token_state, indent=4, sort_keys=True)))

    # Get user Claims from Id Token for signed in display
    if("token" in request.cookies and "id_token" in request.cookies):
        id_token_claims = get_claims_from_token(request.cookies["id_token"])
        if id_token_claims:
            if "sub" in id_token_claims:
                okta_admin = OktaAdmin(session)
                user = okta_admin.get_user(id_token_claims["sub"])
                # print("user: {0}".format(user))
                modal_options = get_modal_options(id_token_claims["sub"])

    if not user:
        getNewTokenUrl = get_oauth_authorize_url()

    response = make_response(
        render_template(
            "index.html",
            site_config=session,
            user=user,
            modal_options=modal_options,
            state_token=state_token,
            show_mfa_enroll=show_mfa_enroll,
            show_bdv=show_bdv,
            okta_widget_container_id="okta-login-container",
            getNewTokenUrl=getNewTokenUrl
        )
    )

    handle_invalid_tokens(session, response)

    return response

@app.route("/profile", methods=["GET"])
@authenticated
def get_profile():
    print("get_profile()")
    user = None
    factors = None

    if ("token" in request.cookies and "id_token" in request.cookies):
        id_token_claims = get_claims_from_token(request.cookies["id_token"])

        if "sub" in id_token_claims:
            okta_admin = OktaAdmin(session)
            user = okta_admin.get_user(id_token_claims["sub"])
            user_profile = user["profile"]
            app_user = okta_admin.get_user_application_by_current_client_id(user["id"])
            print(json.dumps(app_user))
            app_user_profile = app_user["profile"]
            #print("user: {0}".format(user))

            # get a list of enrolled factors
            factors = get_enrolled_factors(user["id"])

    response = make_response(
        render_template(
            "profile.html",
            site_config=session,
            user=user,
            user_profile=user_profile,
            app_user=app_user_profile,
            factors=factors,
            claims=id_token_claims,
            okta_widget_container_id="okta-login-container",
            getNewTokenUrl=""
        )
    )

    return response

@app.route("/profile/<user_id>", methods=["POST"])
@authenticated
def post_profile(user_id):
    print("post_profile()")
    okta_admin = OktaAdmin(session)

    body = request.get_json()
    user_profile = body["user_profile"]
    app_profile = body["app_profile"]
    user_response = okta_admin.update_user(user_id, user_profile)
    response = okta_admin.update_application_user_profile(user_id, app_profile)

    return json.dumps(response)

@app.route('/login-form')
@apply_remote_config
def login_form():
    """ handler for the login form url path of the app """
    print("login_form()")
    user = None
    modal_options = None
    state_token = request.args.get("stateToken")
    print("state_token: {0}".format(state_token))

    session["current_title"] = "{0} | {1} Sign In".format(session["base_title"], session["app_title"])

    response = make_response(
        render_template(
            "login.html",
            site_config=session,
            user=user,
            modal_options=modal_options,
            state_token=state_token,
            okta_widget_container_id="okta-login-full-container",
            getNewTokenUrl=""
        )
    )

    handle_invalid_tokens(session, response)

    return response


@app.route('/help')
@apply_remote_config
def help():
    """ handler for the login form url path of the app """
    print("login_form()")
    user = None
    modal_options = None
    state_token = request.args.get("stateToken")
    print("state_token: {0}".format(state_token))

    session["current_title"] = "{0} | {1} Help".format(session["base_title"], session["app_title"])

    response = make_response(
        render_template(
            "faq.html",
            site_config=session,
            user=user,
            modal_options=modal_options,
            state_token=state_token,
            okta_widget_container_id="okta-login-full-container",
            getNewTokenUrl=""
        )
    )

    handle_invalid_tokens(session, response)

    return response


@app.route('/oidc', methods=["POST"])
def oidc():
    """ handler for the oidc call back of the app """
    print("oidc()")
    response = None
    print(request.form)
    has_app_level_mfa_policy = False

    if "error" in request.form:
        print("ERROR: {0}, MESSAGE: {1}".format(request.form["error"], request.form["error_description"]))
        if ("The client specified not to prompt, but the client app requires re-authentication or MFA." == request.form["error_description"]):
            has_app_level_mfa_policy = True

    # if session["state"] == request.form["state"]:
    if "code" in request.form:
        oidc_code = request.form["code"]
        #  print("oidc_code: {0}".format(oidc_code))
        okta_auth = OktaAuth(session)
        oauth_token = okta_auth.get_oauth_token(
            code=oidc_code,
            grant_type="authorization_code",
            auth_options={
                "client_id": session["client_id"],
                "client_secret": session["client_secret"],
            }
        )
        print("oauth_token: {0}".format(json.dumps(oauth_token, indent=4, sort_keys=True)))
        app_landing_page_url = session["app_base_url"]
        print("app landing page {0}".format(app_landing_page_url))

        response = make_response(redirect(app_landing_page_url))
        response.set_cookie('token', oauth_token["access_token"])
        response.set_cookie('id_token', oauth_token["id_token"])
    elif "error" in request.form:
        # Error occured with Accessing the patient portal

        if has_app_level_mfa_policy:
            response = make_response(
                render_template(
                    "error.html",
                    site_config=session,
                    error_message="Failed to Authenticate.  Please remove App Level MFA Policy and use a Global MFA Policy. Error: {0} - {1}".format(
                        request.form["error"],
                        request.form["error_description"]
                        )
                )
            )
        else:
            response = make_response(
                render_template(
                    "error.html",
                    site_config=session,
                    error_message="Failed to Authenticate.  Check to make sure the user has patient access to the application. Error: {0} - {1}".format(
                        request.form["error"],
                        request.form["error_description"]
                        )
                )
            )
    else:
        # catch all error
        response = make_response(
            render_template(
                "error.html",
                site_config=session,
                error_message="Failed to Authenticate.  Check to make sure the user has access to the application."
            )
        )

    session.pop("state", None)

    return response


@app.route('/login', methods=["POST"])
@apply_remote_config
def login():
    """ Handle either full form post redirect or a json response with redirect url """
    print("login()")
    login_form_data = request.get_json()

    return json.dumps(create_login_response(login_form_data["username"], login_form_data["password"], session))


@app.route('/login/<session_id>', methods=["POST"])
@apply_remote_config
def login_clear_session(session_id=None):
    """ Handle either full form post redirect or a json response with redirect url """
    print("login_clear_session()")
    login_form_data = request.get_json()

    if session_id:
        okta_admin = OktaAdmin(session)
        okta_admin.close_session(session_id)

    return json.dumps(create_login_response(login_form_data["username"], login_form_data["password"], session))


@app.route('/login-token/<token>', methods=["POST"])
@apply_remote_config
def login_token(token):
    """ Handle either full form post redirect or a json response with redirect url """
    print("login_token()")
    redirect_url = "/"

    # print("authn_json_response: {0}".format(json.dumps(authn_json_response, indent=4, sort_keys=True)))
    if token:
        okta_auth = OktaAuth(session)
        session["state"] = str(uuid.uuid4())
        redirect_url = get_oauth_authorize_url(token)
        # print("redirect_url: {0}".format(redirect_url))

    return make_response(redirect(redirect_url))


@app.route("/logout", methods=["GET"])
@apply_remote_config
def logout():
    print("logout()")
    app_base_url = request.url_root

    if request.url_root.startswith('http://'):
        app_base_url = request.url_root.replace('http://', 'https://', 1)

    redirect_url = "{host}/login/signout?fromURI={redirect_path}".format(
        host=session["okta_org_name"],
        redirect_path=app_base_url
    )

    print("redirect_url: {0}".format(redirect_url))

    response = make_response(redirect(redirect_url))
    response.set_cookie("token", "")
    response.set_cookie("id_token", "")

    return response

"""
routes for MFA verification
"""

@app.route("/verify_totp", methods=["POST"])
def verify_totp():
    print("verify_totp()")
    okta_auth = OktaAuth(session)

    body = request.get_json()
    pass_code = None
    factor_id = body["factor_id"]
    state_token = body["state_token"]

    if "pass_code" in body:
        pass_code = body["pass_code"]

    print("verifying factor ID {0} with code {1} ({2})".format(factor_id, pass_code, state_token))
    response = okta_auth.verify_totp(factor_id, state_token, pass_code)
    return json.dumps(response)

@app.route("/send_push", methods=["POST"])
def send_push():
    print("send_push()")
    okta_auth = OktaAuth(session)

    body = request.get_json()
    factor_id = body["factor_id"]
    state_token = body["state_token"]

    response = okta_auth.send_push(factor_id, state_token)
    return json.dumps(response)

@app.route("/poll_for_push_verification", methods=["POST"])
def poll_for_push_verification():
    print("poll_for_push_verification()")
    okta_auth = OktaAuth(session)

    body = request.get_json()
    factor_id = body["factor_id"]
    state_token = body["state_token"]

    response = okta_auth.send_push(factor_id, state_token)
    return json.dumps(response)

@app.route("/resend_push", methods=["POST"])
def resend_push():
    print("resend_push()")

    body = request.get_json()
    factor_id = body["factor_id"]

    if "state_token" in body:
        okta_auth = OktaAuth(session)
        state_token = body["state_token"]
        response = okta_auth.resend_push(factor_id, state_token)
    else:
        okta_admin = OktaAdmin(session)
        user_id = body["user_id"]
        response = okta_admin.resend_push(user_id, factor_id)

    return json.dumps(response)

@app.route("/verify_answer", methods=["POST"])
def verify_answer():
    print("verify_answer()")
    okta_auth = OktaAuth(session)

    body = request.get_json()
    factor_id = body["factor_id"]
    state_token = body["state_token"]
    answer = body["answer"]

    response = okta_auth.verify_answer(factor_id, state_token, answer)
    return json.dumps(response)

@app.route("/get_authorize_url", methods=["POST"])
def get_authorize_url():
    print("get_authorize_url()")
    okta_auth = OktaAuth(session)

    body = request.get_json()
    session_token = body["session_token"]
    session["state"] = str(uuid.uuid4())
    oauth_authorize_url = get_oauth_authorize_url(session_token)

    response = {
        "authorize_url": oauth_authorize_url
    }
    return json.dumps(response)

"""
end MFA verification routes
"""

"""
routes for MFA enrollment
"""

def get_enrolled_factors(user_id):
    print("get_enrolled_factors()")
    okta_admin = OktaAdmin(session)

    enrolled_factors = okta_admin.list_enrolled_factors(user_id)
    factors = []
    for f in enrolled_factors:
        factor = {}
        factor["id"] = f["id"]
        # default the name to the type, just in case
        factor["name"] = f["factorType"]
        factor["type"] = f["factorType"]
        factor["provider"] = f["provider"]
        factor["vendor"] = f["vendorName"]
        #factor["profile"] = f["profile"]
        factor["sortOrder"] = 100
        factorType = factor["type"]
        provider = factor["provider"]

        if (factorType == "token:software:totp"):
            if (provider == "GOOGLE"):
                factor["name"] = "Google Authenticator"
                factor["profile"] = f["profile"]["credentialId"]
                factor["sortOrder"] = 20
            elif (provider == "OKTA"):
                # don't list Okta Verify OTP
                continue
        elif (factorType == "push"):
            factor["name"] = "Okta Verify"
            if "profile" in f:
                factor["profile"] = f["profile"]["name"]
            else:
                factor["profile"] = None
            factor["sortOrder"] = 10
        elif (factorType == "sms"):
            factor["name"] = "SMS"
            factor["profile"] = f["profile"]["phoneNumber"]
            factor["sortOrder"] = 30
        elif (factorType == "call"):
            factor["name"] = "Voice Call"
            factor["profile"] = f["profile"]["phoneNumber"]
            factor["sortOrder"] = 40
        elif (factorType == "question"):
            factor["name"] = "Security Question"
            factor["profile"] = f["profile"]["questionText"]
            factor["sortOrder"] = 50

        factors.append(factor)

    # return the sorted array
    return sorted(factors, key = lambda i: i["sortOrder"])

@app.route("/get_available_factors/<user_id>", methods=["GET"])
def get_available_factors(user_id):
    print("get_available_factors()")
    okta_admin = OktaAdmin(session)

    available_factors = okta_admin.list_available_factors(user_id)
    factors = []
    for f in available_factors:
        if f["status"] == "NOT_SETUP":
            factorType = f["factorType"]
            provider = f["provider"]

            try:
                phone_number = f["_embedded"]["phones"][0]["profile"]["phoneNumber"]
            except:
                phone_number = None

            factor = {
                "factorType": factorType,
                "provider": provider,
                "phoneNumber": phone_number,
                "name": get_factor_name(factorType, provider)
            }

            factors.append(factor)

    return json.dumps(factors)

@app.route('/get_available_factors_by_state/<state_token>', methods=["POST"])
def get_available_factors_by_state(state_token):
    """ Get all factors available by State Token """
    print("get_available_factors_by_state()")

    okta_auth = OktaAuth(session)
    okta_admin = OktaAdmin(session)

    transaction_state = okta_auth.get_transaction_state(state_token)

    print("transaction_state: {0}".format(json.dumps(transaction_state, indent=4, sort_keys=True)))

    # available_factors = okta_admin.list_available_factors(transaction_state["_embedded"]["user"]["id"])

    return json.dumps(transaction_state)

@app.route("/enroll_push", methods=["POST"])
def enroll_push():
    print("enroll_push()")

    body = request.get_json()
    factor_type = body["factor_type"]
    provider = body["provider"]

    if "state_token" in body:
        # this is an enrollment during the authN process
        okta_auth = OktaAuth(session)
        state_token = body["state_token"]
        response = okta_auth.enroll_push(state_token, factor_type, provider)
    else:
        user_id = body["user_id"]
        okta_admin = OktaAdmin(session)
        response = okta_admin.enroll_push(user_id, factor_type, provider)

    return json.dumps(response)

@app.route("/poll_for_push_enrollment", methods=["POST"])
def poll_for_push_enrollment():
    print("poll_for_push_enrollment()")

    body = request.get_json()
    factor_id = body["factor_id"]

    if "state_token" in body:
        state_token = body["state_token"]
        okta_auth = OktaAuth(session)
        response = okta_auth.poll_for_enrollment_push(factor_id, state_token)
    else:
        user_id = body["user_id"]
        okta_admin = OktaAdmin(session)
        response = okta_admin.poll_for_enrollment_push(user_id, factor_id)

    return json.dumps(response)

@app.route("/enroll_totp", methods=["POST"])
def enroll_totp():
    print("enroll_totp()")

    body = request.get_json()
    factor_type = body["factor_type"]
    provider = body["provider"]

    if "stateToken" in body:
        okta_auth = OktaAuth(session)
        state_token = body["state_token"]
        response = okta_auth.enroll_totp(state_token, factor_type, provider)
    else:
        okta_admin = OktaAdmin(session)
        user_id = body["user_id"]
        response = okta_admin.enroll_totp(user_id, factor_type, provider)

    return json.dumps(response)

@app.route("/enroll_sms_voice", methods=["POST"])
def enroll_sms_voice():
    print("enroll_sms_voice()")

    body = request.get_json()
    factor_type = body["factor_type"]
    provider = body["provider"]
    phone_number = body["phone_number"]

    if "state_token" in body:
        okta_auth = OktaAuth(session)
        state_token = body["state_token"]
        response = okta_auth.enroll_sms_voice(state_token, factor_type, provider, phone_number)
    else:
        okta_admin = OktaAdmin(session)
        user_id = body["user_id"]
        response = okta_admin.enroll_sms_voice(user_id, factor_type, provider, phone_number)

    return json.dumps(response)

@app.route("/enroll_question", methods=["POST"])
def enroll_question():
    print("enroll_question()")

    body = request.get_json()
    factor_type = body["factor_type"]
    provider = body["provider"]
    question = body["question"]
    answer = body["answer"]

    if "state_token" in body:
        okta_auth = OktaAuth(session)
        state_token = body["state_token"]
        response = okta_auth.enroll_question(state_token, factor_type, provider, question, answer)
    else:
        okta_admin = OktaAdmin(session)
        user_id = body["user_id"]
        response = okta_admin.enroll_question(user_id, factor_type, provider, question, answer)

    return json.dumps(response)

@app.route("/list_available_questions", methods=["POST"])
def list_available_questions():
    print("list_available_questions()")
    okta_admin = OktaAdmin(session)

    body = request.get_json()
    user_id = body["user_id"]
    response = okta_admin.list_available_questions(user_id)

    return json.dumps(response)

@app.route("/activate_totp", methods=["POST"])
def activate_totp():
    print("activate_totp()")

    body = request.get_json()
    factor_id = body["factor_id"]
    pass_code = body["pass_code"]

    if "state_token" in body:
        okta_auth = OktaAuth(session)
        state_token = body["state_token"]
        response = okta_auth.activate_totp(factor_id, state_token, pass_code)
    else:
        okta_admin = OktaAdmin(session)
        user_id = body["user_id"]
        response = okta_admin.activate_totp(user_id, factor_id, pass_code)

    return json.dumps(response)

@app.route("/reset_factor/<user_id>/<factor_id>", methods=["GET"])
def reset_factor(user_id, factor_id):
    print("reset_factor()")
    okta_admin = OktaAdmin(session)
    response = okta_admin.delete_factor(user_id, factor_id)

    return json.dumps(response)

"""
end MFA enrollment routes
"""

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

    update_response = okta_admin.update_application_user_profile(user_id, app)

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
    group_name_lookup = "{0}_{1}_patient".format(
                            session["udp_subdomain"],
                            session["demo_app_name"])
    print("group_name_lookup: {0}".format(group_name_lookup))

    patient_groups_response = okta_admin.get_groups_by_name(group_name_lookup)
    print("patient_groups_response: {0}".format(json.dumps(patient_groups_response, indent=4, sort_keys=True)))

    if "errorSummary" in patient_groups_response:
        register_basic_response["errorMessage"] = patient_groups_response["errorSummary"]
        if "errorCauses" in patient_groups_response:
            register_basic_response["errorMessages"] = []
            for error_cause in patient_groups_response["errorCauses"]:
                register_basic_response["errorMessages"].append({
                    "errorMessage": error_cause["errorSummary"]
                })
    else:
        patient_group = patient_groups_response[0]  # Default to first found group by name

        user = {
            "profile": {
                "firstName": "NOT_SET",
                "lastName": "NOT_SET",
                "email": login_form_data["username"],
                "login": session["login_id_prefix"] + login_form_data["username"]
            },
            "credentials": {
                "password": {"value": login_form_data["password"]}
            },
            "groupIds": [
                patient_group["id"]
            ]
        }
        print("user: {0}".format(json.dumps(user, indent=4, sort_keys=True)))
        created_user = okta_admin.create_user(user)
        print("created_user: {0}".format(json.dumps(created_user, indent=4, sort_keys=True)))

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
            register_basic_response["userId"] = created_user["id"]

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
            "lastName": user_form_data["lastName"]
        }
    }

    app_user = {
        "profile": {
            "height": user_form_data["height"],
            "weight": user_form_data["weight"]
        }
    }

    updated_user = okta_admin.update_user(user_id, user)
    # print("updated_user: {0}".format(json.dumps(updated_user, indent=4, sort_keys=True)))
    updated_app_user = okta_admin.update_application_user_profile(user_id, app_user)

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
        register_default_response["app_user"] = updated_app_user
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
            "mobilePhone": user_form_data["mobilePhone"]
        }
    }

    app_user = {
        "profile": {
            "dob": user_form_data["dob"]
        }
    }

    updated_user = okta_admin.update_user(user_id, user)
    updated_app_user = okta_admin.update_application_user_profile(user_id, app_user)
    # print("updated_user: {0}".format(json.dumps(updated_user, indent=4, sort_keys=True)))

    if "errorSummary" in updated_app_user:
        register_alt1_response["errorMessage"] = updated_app_user["errorSummary"]

        if "errorCauses" in updated_app_user:
            register_alt1_response["errorMessages"] = []
            for error_cause in updated_app_user["errorCauses"]:
                register_alt1_response["errorMessages"].append({
                    "errorMessage": error_cause["errorSummary"]
                })
    else:
        register_alt1_response["success"] = True
        register_alt1_response["app_user"] = updated_app_user
        register_alt1_response["user"] = updated_user

    return json.dumps(register_alt1_response)


@app.route("/activate/<user_id>", defaults={'okta_session_id': None}, methods=["GET"])
@app.route("/activate/<user_id>/<okta_session_id>", methods=["GET"])
def activate(user_id, okta_session_id):
    print("activate(user_id, okta_session_id)")

    activation_response = {}
    auth_response = make_response(redirect("/"))

    okta_admin = OktaAdmin(session)

    user = okta_admin.get_user(user_id)

    if user:
        activation_response = okta_admin.activate_user(user_id, send_email=False)
        print("activation_response: {0}".format(json.dumps(activation_response, indent=4, sort_keys=True)))

    if "okta_session_id":
        print("Clearing exsisting session")
        clear_session_response = okta_admin.close_session(okta_session_id)
        print("clear_session_response: {0}".format(json.dumps(clear_session_response, indent=4, sort_keys=True)))

    if "activationToken" in activation_response:
        okta_auth = OktaAuth(session)
        auth_response = okta_auth.authenticate_with_activation_token(activation_response["activationToken"])
        # print("auth_response: {0}".format(json.dumps(auth_response, indent=4, sort_keys=True)))
        if "sessionToken" in auth_response:
            auth_response = login_token(auth_response["sessionToken"])
            # status = MFA_ENROLL
            # status = PASSWORD_RESET
        elif "stateToken" in auth_response:
            if "MFA_ENROLL" == auth_response["status"]:
                auth_response = make_response(redirect("/?stateToken={0}&showMFAEnroll=true".format(auth_response["stateToken"])))
            elif "PASSWORD_RESET" == auth_response["status"]:
                auth_response = make_response(redirect("/?stateToken={0}&showBDV=true".format(auth_response["stateToken"])))
            else:
                auth_response = make_response(redirect("/?stateToken={0}".format(auth_response["stateToken"])))

    return auth_response


@app.route("/activate-account/<user_id>", methods=["GET"])
@apply_remote_config
def activate_account(user_id):
    print("activate_account()")
    print("user_id: {0}".format(user_id))

    user = None
    modal_options = None
    session["current_title"] = "{0} | {1} Sign In".format(session["base_title"], session["app_title"])

    response = make_response(
        render_template(
            "activate.html",
            site_config=session,
            user=user,
            modal_options=modal_options,
            user_id=user_id,
            getNewTokenUrl=""
        )
    )

    response.set_cookie("token", "")
    response.set_cookie("id_token", "")

    handle_invalid_tokens(session, response)

    return response


@app.route("/verify-dob", methods=["POST"])
def verify_dob():
    print("verify_dob()")
    json_data = request.get_json()
    # print(json_data)

    verify_dob_response = {
        "success": False
    }

    okta_auth = OktaAuth(session)
    token_state = okta_auth.get_transaction_state(json_data["stateToken"])
    # print("token_state: {0}".format(json.dumps(token_state, indent=4, sort_keys=True)))

    if "errorSummary" in token_state:
        verify_dob_response["errorMessage"] = token_state["errorSummary"]
    else:
        okta_admin = OktaAdmin(session)
        user = okta_admin.get_user(token_state["_embedded"]["user"]["id"])
        app_user = okta_admin.get_user_application_by_current_client_id(user["id"])
        # print("user: {0}".format(json.dumps(user, indent=4, sort_keys=True)))
        # print("app_user: {0}".format(json.dumps(app_user, indent=4, sort_keys=True)))

        if "errorSummary" in user:
            verify_dob_response["errorMessage"] = user["errorSummary"]
            if "errorCauses" in user:
                verify_dob_response["errorMessages"] = []
                for error_cause in user["errorCauses"]:
                    verify_dob_response["errorMessages"].append({
                        "errorMessage": user["errorSummary"]
                    })
        else:
            if app_user["profile"]["dob"] == json_data["dob"]:
                verify_dob_response["user"] = user
                verify_dob_response["app_user"] = user
                verify_dob_response["success"] = True,
            else:
                verify_dob_response["errorMessage"] = "Your date of birth does not match our records"

    return json.dumps(verify_dob_response)


@app.route("/pre-reg-password-set", methods=["POST"])
def pre_reg_password_set():
    print("pre_reg_password_set()")
    json_data = request.get_json()
    print(json_data)

    password_set_response = {
        "success": False
    }

    okta_auth = OktaAuth(session)
    reset_response = okta_auth.reset_password_with_state_token(json_data["stateToken"], json_data["newPassword"])
    print("reset_response: {0}".format(json.dumps(reset_response, indent=4, sort_keys=True)))

    if "errorSummary" in reset_response:
        password_set_response["errorMessage"] = reset_response["errorSummary"]
        if "errorCauses" in reset_response:
            password_set_response["errorMessages"] = []
            for error_cause in reset_response["errorCauses"]:
                password_set_response["errorMessages"].append({
                    "errorMessage": reset_response["errorSummary"]
                })
    else:
        password_set_response = create_login_response(json_data["username"], json_data["newPassword"], session)

    return json.dumps(password_set_response)


@app.route("/load_users", methods=["GET"])
def load_users():
    print("load_users()")

    response = {
        "status": "success",
        "number_of_users_created": 0
    }

    with open("./test_users.csv", mode='r', encoding='utf-8-sig') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        okta_admin = OktaAdmin(session)
        patient_group = okta_admin.get_groups_by_name(
            "{0}_{1}_patient".format(
                session["udp_subdomain"],
                session["demo_app_name"]))[0]  # Default to first found group by name

        for row in csv_reader:
            print(row)
            exsisting_user = okta_admin.get_user(row["email"])
            if "id" not in exsisting_user:
                print("user: '{0}' not found. Creating.".format(row["email"]))
                new_user = {
                    "profile": {
                        "login": row["email"],
                        "email": row["email"],
                        "firstName": row["first_name"],
                        "lastName": row["last_name"]
                    },
                    "groupIds": [
                        patient_group["id"]
                    ]
                }
                created_user = okta_admin.create_user(new_user, activate_user=False)
                if "id" in created_user:
                    app_user = {
                        "profile": {
                            "dob": row["dob"],
                            "requires_validation": True
                        }
                    }
                    okta_admin.update_application_user_profile(created_user["id"], app_user)

                    #  Send activation email
                    recipients = [{"address": {"email": created_user["profile"]["email"]}}]
                    substitution = {
                        "activation_email": created_user["profile"]["email"],
                        "activation_key": created_user["id"],
                        "udp_subdomain": session["udp_subdomain"],
                        "udp_app_name": session["demo_app_name"],
                        "domain": session["remaining_domain"],
                        "logo_url": session["app_logo"],
                        "first_name": created_user["profile"]["firstName"],
                        "last_name": created_user["profile"]["lastName"]
                    }

                    send_mail(
                        "invite-to-app",
                        recipients,
                        session["spark_post_api_key"],
                        substitution)

                    response["number_of_users_created"] += 1
                else:
                    print("Failed to created user: '{0}' reason: {1}".format(
                        row["email"],
                        json.dumps(created_user, indent=4, sort_keys=True)
                    ))

    return json.dumps(response)


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
