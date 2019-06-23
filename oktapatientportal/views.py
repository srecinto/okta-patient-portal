import os
import json
import uuid


from oktapatientportal import app

from flask import request, session, send_from_directory, redirect, make_response, render_template
from datetime import datetime

from utils.okta import OktaAuth, OktaAdmin
from utils.view import apply_remote_config, handle_invalid_tokens
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
    id_token_claims = None
    modal_options = None

    session["current_title"] = "{0} | {1} Home".format(session["base_title"], session["app_title"])

    # Get user Claims from Id Token for signed in display
    if("token" in request.cookies and "id_token" in request.cookies):
        id_token = request.cookies["id_token"]
        id_token_claims = get_claims_from_token(id_token)
        if id_token_claims:
            if "sub" in id_token_claims:
                modal_options = get_modal_options(id_token_claims["sub"])

    response = make_response(
        render_template(
            "index.html",
            site_config=session,
            id_token_claims=id_token_claims,
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
                "scope": "openid profile email",
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
