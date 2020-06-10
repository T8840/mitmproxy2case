
import io
import logging
from urllib.parse import unquote

import sys
import base64
import zlib
import os
import re
import typing
import yaml
import click

from urllib.parse import urlparse
from datetime import datetime
from datetime import timezone

import mitmproxy
from mitmproxy import connections
from mitmproxy import version
from mitmproxy import ctx
from mitmproxy.utils import strutils
from mitmproxy.net.http import cookies
from mitmproxy import io as mitmio
from mitmproxy.exceptions import FlowReadException



try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

try:
    import simplejson as json
except ImportError:
    import json

ensure_ascii = False
builtin_str = str
str = str
bytes = bytes
basestring = (str, bytes)
numeric_types = (int, float)
integer_types = (int,)

IGNORE_REQUEST_HEADERS = [
    "host",
    "accept",
    "content-length",
    "connection",
    "accept-encoding",
    "accept-language",
    "origin",
    "referer",
    "cache-control",
    "pragma",
    "cookie",
    "upgrade-insecure-requests",
    ":authority",
    ":method",
    ":scheme",
    ":path"
]


def load_har_log_entries(entires):
    try:
        content_json = json.loads(entires)
        return content_json["log"]["entries"]
    except (KeyError, TypeError):
        logging.error("entries content error!")
        sys.exit(1)

def x_www_form_urlencoded(post_data):
    if isinstance(post_data, dict):
        return "&".join([
            u"{}={}".format(key, value)
            for key, value in post_data.items()
        ])
    else:
        return post_data

def convert_x_www_form_urlencoded_to_dict(post_data):
    if isinstance(post_data, str):
        converted_dict = {}
        for k_v in post_data.split("&"):
            try:
                key, value = k_v.split("=")
            except ValueError:
                raise Exception(
                    "Invalid x_www_form_urlencoded data format: {}".format(post_data)
                )
            converted_dict[key] = unquote(value)
        return converted_dict
    else:
        return post_data

def convert_list_to_dict(origin_list):
    return {
        item["name"]: item.get("value")
        for item in origin_list
    }

def dump_yaml(testcase, yaml_file):
    """ dump HAR entries to yaml testcase
    """
    logging.info("dump testcase to YAML format.")
    with io.open(yaml_file, 'w', encoding="utf-8") as outfile:
        yaml.dump(testcase, outfile, allow_unicode=True, default_flow_style=False, indent=4)
    logging.info("Generate YAML testcase successfully: {}".format(yaml_file))


def dump_json(testcase, json_file):
    """ dump HAR entries to json testcase
    """
    logging.info("dump testcase to JSON format.")
    with io.open(json_file, 'w', encoding="utf-8") as outfile:
        my_json_str = json.dumps(testcase, ensure_ascii=ensure_ascii, indent=4)
        if isinstance(my_json_str, bytes):
            my_json_str = my_json_str.decode("utf-8")

        outfile.write(my_json_str)
    logging.info("Generate JSON testcase successfully: {}".format(json_file))



HAR: typing.Dict = {}


def get_filter_rule(file):
    if not os.path.isfile(file):
        raise FileNotFoundError
    fname, fext = os.path.splitext(file)

    with open(file) as data:
        if fext == ".yaml":
            data = yaml.safe_load(data)
        else:
            data = json.load(data)
        ignore = data.get('ignore')
        ignore_rule = ''.join([j for i in ignore for j in i.values()]).replace('/', '').replace('*.', '|').lstrip('|')

        allow_path_rule = data.get('allow').get('path')
        allow_host_rule = data.get('allow').get('host')

        return {
            'ignore_rule':ignore_rule,
            'allow_path_rule' : allow_path_rule,
            'allow_host_rule' : allow_host_rule
            }



def get_entry_from_flow(flow, servers_seen,filter_rules):
    """
       Called when a server response has been received.
    """

    # -1 indicates that these values do not apply to current request
    ssl_time = -1
    connect_time = -1

    if flow.server_conn and flow.server_conn.timestamp_tcp_setup and flow.server_conn.timestamp_start and flow.server_conn not in servers_seen:
        connect_time = (flow.server_conn.timestamp_tcp_setup -
                        flow.server_conn.timestamp_start)

        if flow.server_conn.timestamp_tls_setup is not None:
            ssl_time = (flow.server_conn.timestamp_tls_setup -
                        flow.server_conn.timestamp_tcp_setup)

        servers_seen.add(flow.server_conn)

    # Calculate raw timings from timestamps. DNS timings can not be calculated
    # for lack of a way to measure it. The same goes for HAR blocked.
    # mitmproxy will open a server connection as soon as it receives the host
    # and port from the client connection. So, the time spent waiting is actually
    # spent waiting between request.timestamp_end and response.timestamp_start
    # thus it correlates to HAR wait instead.
    timings_raw = {
        'send': flow.request.timestamp_end - flow.request.timestamp_start if flow.request and flow.request.timestamp_end and flow.request.timestamp_start else -1,
        'receive': flow.response.timestamp_end - flow.response.timestamp_start if flow.response and flow.response.timestamp_start and flow.response.timestamp_end else -1,
        'wait': flow.response.timestamp_start - flow.request.timestamp_end if flow.request and flow.response and flow.response.timestamp_start and flow.request.timestamp_end else -1,
        'connect': connect_time,
        'ssl': ssl_time,
    }

    # HAR timings are integers in ms, so we re-encode the raw timings to that format.
    timings = {
        k: int(1000 * v) if v != -1 else -1
        for k, v in timings_raw.items()
    }

    # full_time is the sum of all timings.
    # Timings set to -1 will be ignored as per spec.
    full_time = sum(v for v in timings.values() if v > -1)

    started_date_time = datetime.fromtimestamp(flow.request.timestamp_start, timezone.utc).isoformat()

    # Response body size and encoding
    response_body_size = len(flow.response.raw_content) if flow.response.raw_content else 0
    response_body_decoded_size = len(flow.response.content) if flow.response.content else 0
    response_body_compression = response_body_decoded_size - response_body_size

    entry = {
        "startedDateTime": started_date_time,
        "time": full_time,
        "request": {
            "method": flow.request.method,
            "url": flow.request.url,
            "httpVersion": flow.request.http_version,
            "cookies": format_request_cookies(flow.request.cookies.fields),
            "headers": name_value(flow.request.headers),
            "queryString": name_value(flow.request.query or {}),
            "headersSize": len(str(flow.request.headers)),
            "bodySize": len(flow.request.content),
        },
        "response": {
            "status": flow.response.status_code,
            "statusText": flow.response.reason,
            "httpVersion": flow.response.http_version,
            "cookies": format_response_cookies(flow.response.cookies.fields),
            "headers": name_value(flow.response.headers),
            "content": {
                "size": response_body_size,
                "compression": response_body_compression,
                "mimeType": flow.response.headers.get('Content-Type', '')
            },
            "redirectURL": flow.response.headers.get('Location', ''),
            "headersSize": len(str(flow.response.headers)),
            "bodySize": response_body_size,
        },
        "cache": {},
        "timings": timings,
    }

    # Store binary data as base64
    if strutils.is_mostly_bin(flow.response.content):
        entry["response"]["content"]["text"] = base64.b64encode(flow.response.content).decode()
        entry["response"]["content"]["encoding"] = "base64"
    else:
        entry["response"]["content"]["text"] = flow.response.get_text(strict=False)

    if flow.request.method in ["POST", "PUT", "PATCH"]:
        params = [
            {"name": a, "value": b}
            for a, b in flow.request.urlencoded_form.items(multi=True)
        ]
        entry["request"]["postData"] = {
            "mimeType": flow.request.headers.get("Content-Type", ""),
            "text": flow.request.get_text(strict=False),
            "params": params
        }


    if flow.server_conn.connected():
        entry["serverIPAddress"] = str(flow.server_conn.ip_address[0])

    ignore_rule = filter_rules.get('ignore_rule')
    allow_path_rule = filter_rules.get('allow_path_rule')
    allow_host_rule = filter_rules.get('allow_host_rule')

    if ignore_rule:
        ignore_pattern = f'.*\.({ignore_rule})$'
        m = re.match(ignore_pattern,flow.request.url)
        if m!=None:
            entry=None
    if allow_path_rule or allow_host_rule:
        url_info = urlparse(flow.request.url)
        # print(url_info.path)
        if url_info.path not in allow_path_rule:
            entry=None

    return entry


def done():
    """
        Called once on script shutdown, after any other events.
    """
    if ctx.options.hardump:
        json_dump: str = json.dumps(HAR, indent=2)

        if ctx.options.hardump == '-':
            mitmproxy.ctx.log(json_dump)
        else:
            raw: bytes = json_dump.encode()
            if ctx.options.hardump.endswith('.zhar'):
                raw = zlib.compress(raw, 9)

            with open(os.path.expanduser(ctx.options.hardump), "wb") as f:
                f.write(raw)

            mitmproxy.ctx.log("HAR dump finished (wrote %s bytes to file)" % len(json_dump))


def format_cookies(cookie_list):
    rv = []

    for name, value, attrs in cookie_list:
        cookie_har = {
            "name": name,
            "value": value,
        }

        # HAR only needs some attributes
        for key in ["path", "domain", "comment"]:
            if key in attrs:
                cookie_har[key] = attrs[key]

        # These keys need to be boolean!
        for key in ["httpOnly", "secure"]:
            cookie_har[key] = bool(key in attrs)

        # Expiration time needs to be formatted
        expire_ts = cookies.get_expiration_ts(attrs)
        if expire_ts is not None:
            cookie_har["expires"] = datetime.fromtimestamp(expire_ts, timezone.utc).isoformat()

        rv.append(cookie_har)

    return rv


def format_request_cookies(fields):
    return format_cookies(cookies.group_cookies(fields))


def format_response_cookies(fields):
    return format_cookies((c[0], c[1][0], c[1][1]) for c in fields)


def name_value(obj):
    """
        Convert (key, value) pairs to HAR format.
    """
    return [{"name": k, "value": v} for k, v in obj.items()]


class IteratorAsList(list):
    def __init__(self, it):
        self.it = it

    def __iter__(self):
        return self.it

    def __len__(self):
        return 1


def flow_parser(record_flow_path,filter_rule=None):
    servers_seen = set()
    if not os.path.isfile(record_flow_path):
        raise FileNotFoundError
    with open(record_flow_path, "rb") as logfile:
        freader = mitmio.FlowReader(logfile)
        try:
            har = {
                "log": {
                    "version": "1.2",
                    "creator": {
                        "name": "mitmproxy2har",
                        "version": "0.1"
                    },
                    "entries": IteratorAsList(
                        map(lambda entry: get_entry_from_flow(entry, servers_seen,filter_rule), freader.stream()))
                }
            }

            result = json.dumps(har, indent=4)
            return result
        except FlowReadException as e:
            print("Flow file corrupted: {}".format(e))



class HarParser(object):
    def __init__(self, entries, filter_str=None, exclude_str=None):
        self.entries = entries
        self.filter_str = filter_str
        self.exclude_str = exclude_str or ""

    def __make_request_url(self, teststep_dict, entry_json):
        """ parse HAR entry request url and queryString, and make teststep url and params
        Args:
            entry_json (dict):
                {
                    "request": {
                        "url": "https://httprunner.top/home?v=1&w=2",
                        "queryString": [
                            {"name": "v", "value": "1"},
                            {"name": "w", "value": "2"}
                        ],
                    },
                    "response": {}
                }
        Returns:
            {
                "name: "/home",
                "request": {
                    url: "https://httprunner.top/home",
                    params: {"v": "1", "w": "2"}
                }
            }
        """
        request_params = convert_list_to_dict(
            entry_json["request"].get("queryString", [])
        )

        url = entry_json["request"].get("url")
        if not url:
            logging.exception("url missed in request.")
            sys.exit(1)

        parsed_object = urlparse(url)
        if request_params:
            parsed_object = parsed_object._replace(query='')
            teststep_dict["request"]["url"] = parsed_object.geturl()
            teststep_dict["request"]["params"] = request_params
        else:
            teststep_dict["request"]["url"] = url

        teststep_dict["name"] = parsed_object.path

    def __make_request_method(self, teststep_dict, entry_json):
        """ parse HAR entry request method, and make teststep method.
        """
        method = entry_json["request"].get("method")
        if not method:
            logging.exception("method missed in request.")
            sys.exit(1)

        teststep_dict["request"]["method"] = method

    def __make_request_headers(self, teststep_dict, entry_json):
        """ parse HAR entry request headers, and make teststep headers.
            header in IGNORE_REQUEST_HEADERS will be ignored.
        Args:
            entry_json (dict):
                {
                    "request": {
                        "headers": [
                            {"name": "Host", "value": "httprunner.top"},
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "User-Agent", "value": "iOS/10.3"}
                        ],
                    },
                    "response": {}
                }
        Returns:
            {
                "request": {
                    headers: {"Content-Type": "application/json"}
            }
        """
        teststep_headers = {}
        for header in entry_json["request"].get("headers", []):
            if header["name"].lower() in IGNORE_REQUEST_HEADERS:
                continue

            teststep_headers[header["name"]] = header["value"]

        if teststep_headers:
            teststep_dict["request"]["headers"] = teststep_headers

    def _make_request_data(self, teststep_dict, entry_json):
        """ parse HAR entry request data, and make teststep request data
        Args:
            entry_json (dict):
                {
                    "request": {
                        "method": "POST",
                        "postData": {
                            "mimeType": "application/x-www-form-urlencoded; charset=utf-8",
                            "params": [
                                {"name": "a", "value": 1},
                                {"name": "b", "value": "2"}
                            }
                        },
                    },
                    "response": {...}
                }
        Returns:
            {
                "request": {
                    "method": "POST",
                    "data": {"v": "1", "w": "2"}
                }
            }
        """
        method = entry_json["request"].get("method")
        if method in ["POST", "PUT", "PATCH"]:
            postData = entry_json["request"].get("postData", {})
            mimeType = postData.get("mimeType")

            # Note that text and params fields are mutually exclusive.
            if "text" in postData:
                post_data = postData.get("text")
            else:
                params = postData.get("params", [])
                post_data = convert_list_to_dict(params)

            request_data_key = "data"
            if not mimeType:
                pass
            elif mimeType.startswith("application/json"):
                try:
                    post_data = json.loads(post_data)
                    request_data_key = "json"
                except JSONDecodeError:
                    pass
            elif mimeType.startswith("application/x-www-form-urlencoded"):
                post_data = convert_x_www_form_urlencoded_to_dict(post_data)
            else:
                # TODO: make compatible with more mimeType
                pass

            teststep_dict["request"][request_data_key] = post_data

    def _make_validate(self, teststep_dict, entry_json):
        """ parse HAR entry response and make teststep validate.
        Args:
            entry_json (dict):
                {
                    "request": {},
                    "response": {
                        "status": 200,
                        "headers": [
                            {
                                "name": "Content-Type",
                                "value": "application/json; charset=utf-8"
                            },
                        ],
                        "content": {
                            "size": 71,
                            "mimeType": "application/json; charset=utf-8",
                            "text": "eyJJc1N1Y2Nlc3MiOnRydWUsIkNvZGUiOjIwMCwiTWVzc2FnZSI6bnVsbCwiVmFsdWUiOnsiQmxuUmVzdWx0Ijp0cnVlfX0=",
                            "encoding": "base64"
                        }
                    }
                }
        Returns:
            {
                "validate": [
                    {"eq": ["status_code", 200]}
                ]
            }
        """
        teststep_dict["validate"].append(
            {"eq": ["status_code", entry_json["response"].get("status")]}
        )

        resp_content_dict = entry_json["response"].get("content")

        headers_mapping = convert_list_to_dict(
            entry_json["response"].get("headers", [])
        )
        if "Content-Type" in headers_mapping:
            teststep_dict["validate"].append(
                {"eq": ["headers.Content-Type", headers_mapping["Content-Type"]]}
            )

        text = resp_content_dict.get("text")
        if not text:
            return

        mime_type = resp_content_dict.get("mimeType")
        if mime_type and mime_type.startswith("application/json"):

            encoding = resp_content_dict.get("encoding")
            if encoding and encoding == "base64":
                content = base64.b64decode(text).decode('utf-8')
            else:
                content = text

            try:
                resp_content_json = json.loads(content)
            except JSONDecodeError:
                logging.warning(
                    "response content can not be loaded as json: {}".format(content.encode("utf-8"))
                )
                return

            if not isinstance(resp_content_json, dict):
                return

            for key, value in resp_content_json.items():
                if isinstance(value, (dict, list)):
                    continue

                teststep_dict["validate"].append(
                    {"eq": ["content.{}".format(key), value]}
                )

    def _prepare_teststep(self, entry_json):
        """ extract info from entry dict and make teststep
        Args:
            entry_json (dict):
                {
                    "request": {
                        "method": "POST",
                        "url": "https://httprunner.top/api/v1/Account/Login",
                        "headers": [],
                        "queryString": [],
                        "postData": {},
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {}
                    }
                }
        """
        teststep_dict = {
            "name": "",
            "request": {},
            "validate": []
        }

        self.__make_request_url(teststep_dict, entry_json)
        self.__make_request_method(teststep_dict, entry_json)
        self.__make_request_headers(teststep_dict, entry_json)
        self._make_request_data(teststep_dict, entry_json)
        self._make_validate(teststep_dict, entry_json)

        return teststep_dict

    def _prepare_config(self):
        """ prepare config block.
        """
        return {
            "name": "testcase description",
            "variables": {}
        }

    def _prepare_teststeps(self, fmt_version):
        """ make teststep list.
            teststeps list are parsed from HAR log entries list.
        """
        def is_exclude(url, exclude_str):
            exclude_str_list = exclude_str.split("|")
            for exclude_str in exclude_str_list:
                if exclude_str and exclude_str in url:
                    return True

            return False

        teststeps = []

        log_entries = load_har_log_entries(self.entries)
        for entry_json in log_entries:
            if entry_json == None:
                continue
            url = entry_json["request"].get("url")
            if self.filter_str and self.filter_str not in url:
                continue

            if is_exclude(url, self.exclude_str):
                continue

            if fmt_version == "v1":
                teststeps.append(
                    {"test": self._prepare_teststep(entry_json)}
                )
            else:
                # v2
                teststeps.append(
                    self._prepare_teststep(entry_json)
                )

        return teststeps

    def _make_testcase(self, fmt_version):
        """ Extract info from HAR file and prepare for testcase
        """
        logging.debug("Extract info from HAR file and prepare for testcase.")

        config = self._prepare_config()
        teststeps = self._prepare_teststeps(fmt_version)

        if fmt_version == "v1":
            testcase = []
            testcase.append(
                {"config": config}
            )
            testcase.extend(teststeps)
        else:
            # v2
            testcase = {
                "config": config,
                "teststeps": teststeps
            }

        return testcase

    def gen_testcase(self, harfile='Cases',file_type="JSON", fmt_version="v2"):
        # harfile = os.path.splitext(self.har_file_path)[0]
        output_testcase_file = "{}.{}".format(harfile, file_type.lower())
        logging.info("Start to generate testcase.")
        testcase = self._make_testcase(fmt_version)
        logging.debug("prepared testcase: {}".format(testcase))

        if file_type == "JSON":
            dump_json(testcase, output_testcase_file)
        else:
            dump_yaml(testcase, output_testcase_file)


@click.command()
@click.option('--filter',help="You can use the default: filter.yaml")
@click.argument('recordfile')
def cli(recordfile,filter):
    if not os.path.isfile(recordfile):
        raise FileNotFoundError
    entries = flow_parser(recordfile, get_filter_rule(filter))
    HarParser(entries).gen_testcase()





