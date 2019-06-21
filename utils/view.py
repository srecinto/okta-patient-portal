import json
import requests


from oktapatientportal import default_settings, secure_settings

from functools import wraps

from flask import request, session

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

            print("Session Dump: {0}".format(session))

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