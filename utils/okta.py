import base64

from utils.rest import RestUtil


class OktaAuth:

    okta_config = None

    def __init__(self, okta_config):
        print("OktaAuth init()")
        if okta_config:
            self.okta_config = okta_config
            # print("self.okta_config: {0}".format(self.okta_config))
        else:
            raise Exception("Requires okta_config")

    def authenticate(self, username, password, additional_options=None, headers=None):
        print("OktaAuth.authenticate()")
        url = "{host}/api/v1/authn".format(host=self.okta_config["base_url"])
        okta_headers = OktaUtil.get_default_okta_headers(headers)

        body = {
            "username": username,
            "password": password,
        }

        if additional_options:
            RestUtil.map_attribute("audience", additional_options, body)
            RestUtil.map_attribute("relayState", additional_options, body)
            RestUtil.map_attribute("options", additional_options, body)
            RestUtil.map_attribute("context", additional_options, body)
            RestUtil.map_attribute("token", additional_options, body)

        return RestUtil.execute_post(url, body, okta_headers)

    def authenticate_with_activation_token(self, token, headers=None):
        print("OktaAuth.authenticate_with_activation_token()")
        url = "{host}/api/v1/authn".format(host=self.okta_config["base_url"])
        okta_headers = OktaUtil.get_protected_okta_headers(self.okta_config)

        body = {
            "token": token
        }

        return RestUtil.execute_post(url, body, okta_headers)

    def get_transaction_state(self, token, headers=None):
        print("OktaAuth.authenticate_with_activation_token()")
        url = "{host}/api/v1/authn".format(host=self.okta_config["base_url"])
        okta_headers = OktaUtil.get_default_okta_headers(self.okta_config)

        body = {
            "stateToken": token
        }

        return RestUtil.execute_post(url, body, okta_headers)

    def reset_password_with_state_token(self, token, password, headers=None):
        print("OktaAuth.reset_password_with_state_token()")
        url = "{host}/api/v1/authn/credentials/reset_password".format(host=self.okta_config["base_url"])
        okta_headers = OktaUtil.get_protected_okta_headers(self.okta_config)

        body = {
            "stateToken": token,
            "newPassword": password
        }

        return RestUtil.execute_post(url, body, okta_headers)

    def create_oauth_authorize_url(self, response_type, state, auth_options):
        print("OktaAuth.create_oauth_authorize_url()")

        url = (
            "{issuer}/v1/authorize?"
            "response_type={response_type}&"
            "client_id={clint_id}&"
            "redirect_uri={redirect_uri}&"
            "state={state}"
        ).format(
            issuer=self.okta_config["issuer"],
            clint_id=self.okta_config["client_id"],
            redirect_uri=self.okta_config["redirect_uri"],
            state=state,
            response_type=response_type
        )

        if auth_options:
            for key in auth_options:
                url = "{url}&{key}={value}".format(url=url, key=key, value=auth_options[key])

        return url

    def get_oauth_token(self, code, grant_type, auth_options=None, headers=None):
        print("OktaAuth.get_oauth_token()")
        okta_headers = OktaUtil.get_oauth_okta_headers(headers)

        url = (
            "{issuer}/v1/token?"
            "grant_type={grant_type}&"
            "code={code}&"
            "redirect_uri={redirect_uri}"
        ).format(
            issuer=self.okta_config["issuer"],
            code=code,
            redirect_uri=self.okta_config["redirect_uri"],
            grant_type=grant_type
        )

        body = {
            "authorization_code": code
        }

        if auth_options:
            for key in auth_options:
                url = "{url}&{key}={value}".format(url=url, key=key, value=auth_options[key])

        return RestUtil.execute_post(url, body, okta_headers)

    def introspect(self, token, headers=None):
        print("OktaAuth.introspect()")
        okta_headers = OktaUtil.get_oauth_okta_headers(headers, self.okta_config["client_id"], self.okta_config["client_secret"])

        url = "{issuer}/v1/introspect?token={token}".format(
            issuer=self.okta_config["issuer"],
            token=token)
        body = {}

        return RestUtil.execute_post(url, body, okta_headers)

    def userinfo(self, token, headers=None):
        print("OktaAuth.userinfo()")
        okta_headers = OktaUtil.get_oauth_okta_bearer_token_headers(headers, token)

        url = "{issuer}/v1/userinfo?token={token}".format(
            issuer=self.okta_config["issuer"],
            token=token)
        body = {}

        return RestUtil.execute_post(url, body, okta_headers)


class OktaAdmin:

    okta_config = None

    def __init__(self, okta_config):
        print("OktaAdmin init()")
        if okta_config:
            self.okta_config = okta_config
        else:
            raise Exception("Requires okta_config")

    def get_user(self, user_id):
        print("OktaAdmin.get_user(user_id)")
        okta_headers = OktaUtil.get_protected_okta_headers(self.okta_config)
        url = "{base_url}/api/v1/users/{user_id}".format(
            base_url=self.okta_config["base_url"],
            user_id=user_id)
        body = {}

        return RestUtil.execute_get(url, body, okta_headers)

    def create_user(self, user, activate_user=False):
        print("OktaAdmin.create_user(user)")
        okta_headers = OktaUtil.get_protected_okta_headers(self.okta_config)
        url = "{base_url}/api/v1/users?activate={activate_user}".format(
            base_url=self.okta_config["base_url"],
            activate_user=activate_user)

        return RestUtil.execute_post(url, user, okta_headers)

    def update_user(self, user_id, user):
        print("OktaAdmin.update_user()")
        okta_headers = OktaUtil.get_protected_okta_headers(self.okta_config)
        url = "{base_url}/api/v1/users/{user_id}".format(
            base_url=self.okta_config["base_url"],
            user_id=user_id)

        return RestUtil.execute_post(url, user, okta_headers)

    def activate_user(self, user_id, send_email=True):
        print("OktaAdmin.activate_user(user_id)")
        okta_headers = OktaUtil.get_protected_okta_headers(self.okta_config)
        url = "{base_url}/api/v1/users/{user_id}/lifecycle/activate/?sendEmail={send_email}".format(
            base_url=self.okta_config["base_url"],
            user_id=user_id,
            send_email=str(send_email).lower())
        body = {}

        return RestUtil.execute_post(url, body, okta_headers)

    def get_groups_by_name(self, name):
        print("OktaAdmin.get_groups_by_name(user_id)")
        okta_headers = OktaUtil.get_protected_okta_headers(self.okta_config)
        url = "{base_url}/api/v1/groups?q={name}".format(
            base_url=self.okta_config["base_url"],
            name=name)
        body = {}

        return RestUtil.execute_get(url, body, okta_headers)

    def assign_user_to_group(self, group_id, user_id):
        print("OktaAdmin.assign_user_to_group(user_id)")
        okta_headers = OktaUtil.get_protected_okta_headers(self.okta_config)
        url = "{base_url}/api/v1//groups/{group_id}/users/{user_id}".format(
            base_url=self.okta_config["base_url"],
            group_id=group_id,
            user_id=user_id)
        body = {}

        return RestUtil.execute_put(url, body, okta_headers)

    def get_applications_by_user_id(self, user_id):
        print("OktaAdmin.get_applications_by_user_id(user_id)")
        okta_headers = OktaUtil.get_protected_okta_headers(self.okta_config)
        url = "{base_url}/api/v1/apps/?filter=user.id+eq+\"{user_id}\"".format(
            base_url=self.okta_config["base_url"],
            user_id=user_id)
        body = {}

        return RestUtil.execute_get(url, body, okta_headers)

    def get_user_application_by_current_client_id(self, user_id):
        print("OktaAdmin.get_user_application_by_current_client_id(user_id)")
        okta_headers = OktaUtil.get_protected_okta_headers(self.okta_config)

        url = "{base_url}/api/v1/apps/{app_id}/users/{user_id}".format(
            base_url=self.okta_config["base_url"],
            app_id=self.okta_config["client_id"],
            user_id=user_id)
        body = {}

        return RestUtil.execute_get(url, body, okta_headers)

    def update_application_user_profile(self, app_id, user_id, app_user_profile):
        print("OktaAdmin.update_application_user_profile(app_id, user_id, app_user_profile)")

        okta_headers = OktaUtil.get_protected_okta_headers(self.okta_config)
        url = "{base_url}/api/v1/apps/{app_id}/users/{user_id}".format(
            base_url=self.okta_config["base_url"],
            app_id=app_id,
            user_id=user_id)

        body = {
            "profile": app_user_profile["profile"]
        }

        return RestUtil.execute_post(url, body, okta_headers)

    def close_session(self, session_id):
        print("OktaAdmin.close_session(session_id)")
        okta_headers = OktaUtil.get_protected_okta_headers(self.okta_config)
        url = "{base_url}/api/v1/sessions/{session_id}".format(
            base_url=self.okta_config["base_url"],
            session_id=session_id)

        print("url: {0}".format(url))

        body = {}

        return RestUtil.execute_delete(url, body, okta_headers)


class OktaUtil:

    @staticmethod
    def get_default_okta_headers(headers):
        okta_default_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        return okta_default_headers

    @staticmethod
    def get_protected_okta_headers(okta_config):
        okta_api_token = okta_config["okta_api_token"]
        okta_protected_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "SSWS {0}".format(okta_api_token)
        }

        return okta_protected_headers

    @staticmethod
    def get_oauth_okta_headers(headers, client_id=None, client_secret=None):
        okta_oauth_headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        if client_id and client_secret:
            okta_oauth_headers["Authorization"] = "Basic {0}".format(OktaUtil.get_encoded_auth(client_id, client_secret))

        return okta_oauth_headers

    @staticmethod
    def get_oauth_okta_bearer_token_headers(headers, token):
        okta_oauth_headers = {"Authorization": "Bearer {0}".format(token)}

        return okta_oauth_headers

    @staticmethod
    def get_encoded_auth(client_id, client_secret):
        auth_raw = "{client_id}:{client_secret}".format(
            client_id=client_id,
            client_secret=client_secret
        )

        encoded_auth = base64.b64encode(bytes(auth_raw, 'UTF-8')).decode("UTF-8")

        return encoded_auth
