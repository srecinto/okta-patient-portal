import requests


class RestUtil:

    @staticmethod
    def execute_post(url, body=None, headers=None):
        rest_response = requests.post(url, headers=headers, json=body)
        return RestUtil.handle_response_as_json(rest_response)

    @staticmethod
    def execute_put(url, body=None, headers=None):
        rest_response = requests.put(url, headers=headers, json=body)
        return RestUtil.handle_response_as_json(rest_response)

    @staticmethod
    def execute_delete(url, body=None, headers=None):
        rest_response = requests.delete(url, headers=headers, json=body)
        return RestUtil.handle_response_as_json(rest_response)

    @staticmethod
    def execute_get(url, body=None, headers=None):
        print("#####")
        print("url: {}".format(url))
        print("header: {}".format(headers))
        print("body: {}".format(body))
        try:
            # rest_response = requests.get(url, headers=headers, json=body)
            rest_response = requests.request("GET", url, headers=headers)
            rest_response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            print("Exception excute_get(): {}".format(e))
            raise
        return RestUtil.handle_response_as_json(rest_response)

    @staticmethod
    def handle_response_as_json(rest_response):
        try:
            response_json = rest_response.json()
        except Exception as ex:
            print("Exception: {0}".format(ex))
            response_json = {"status": "none"}

        # print(json.dumps(response_json, indent=4, sort_keys=True))
        return response_json

    @staticmethod
    def map_attribute(mapping_name, source, target):
        if target and source:
            if mapping_name in source:
                target[mapping_name] = source[mapping_name]
