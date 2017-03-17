#coding:utf-8
import datetime
import json
import mock
import os
import pytest
import re
import sys

from tornado.httputil import url_concat
from mpin_utils import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR + '/..')

import dta

http_server = None

@pytest.fixture
def app(httpserver):
    dta.options.parse_config_file(dta.options.configFile)

    # Set Log level
    #dta.log.setLevel(dta.getLogLevel(dta.options.logLevel))
    #dta.log.setLevel("DEBUG")

    #dta.detectProxy()

    # Load the credentials from file
    dta.credentialsFile = dta.options.credentialsFile
    dta.Keys.loadFromFile(dta.credentialsFile)

    # TMP fix for 'ValueError: I/O operation on closed epoll fd'
    # Fixed in Tornado 4.2
    dta.tornado.ioloop.IOLoop.instance()

    # Sync time to CertiVox time server
    mockResponse = {"Fallback": False, "Format": "u", "Epoch": "1459436400.000", "Time": "2016-04-01 00:00:00Z"}
    httpserver.serve_content(json.dumps(mockResponse), 200)
    with mock.patch("dta.Keys.timeServer", return_value="{0}/".format(httpserver.url)):
        if dta.options.syncTime:
            dta.Time.getTime(wait=True)

    if dta.options.backup and dta.options.encrypt_master_secret and not dta.options.passphrase:
        dta.options.passphrase = dta.getpass.getpass("Please enter passphrase:")

    with mock.patch("dta.Keys.timeServer", return_value="{0}/".format(httpserver.url)), mock.patch("dta.secrets.MasterSecret._get_master_secret", return_value=("1ff665a4f883573197e6b1aa874778f8dbf18c773ff64f9bc481930a4cf89322".decode("hex"), datetime.datetime.strptime("2016-10-26 02:18:06", "%Y-%m-%d %H:%M:%S"))):
        global http_server
        http_server = dta.Application()

        return http_server

@pytest.mark.gen_test
def test_ServerSecretHandlerOK(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    expires = "2100-04-01T00:01:00Z"
    signature = "5f9b5e7b15461e840c3bdcaac91a1964a93466cad743cf2f0bfed1701e91cb7c"
    hashServerSecret = "83acd17b5a6973286057f248a96ce805c5bd74f44f878ba6e369fece6af87d22"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T00:00:30.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.Keys, "app_id", appId), mock.patch.object(dta.Keys, "app_key", appKey), mock.patch.object(dta.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == "*"
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        assert responseJson["serverSecret"] == "1a6b98201e56be6b1b3c87d088f7cfb0993c6d7e2b841bc000b393ab639060e9232f688e818c51c2ed9ee0ff6d21b7b6df2bb0f0c9924c22c272c2a0373fa37a2021ee8f5826cfacd3adb54b47f49246714bd6c13a841f5ab16240c00415acac20178e58f1c7c0f3eadc12cc24cb54f8b6092deaa28bdfa618f183115dc32303"
        assert responseJson["startTime"] == "2016-10-26T02:18:06Z"
        assert responseJson["message"] == "OK"

        mockLog.assert_called_with("200 GET /serverSecret 127.0.0.1 ".decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerUnnessesaryKey(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    mobile = ""

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'mobile': mobile,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. mobile argument unnecessary"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format("", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerAppIdKeyError(http_client, base_url, mocker):
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Missing argument app_id"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format("", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerAppIdInvalidCharacterFull(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0Ａ"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. app_id argument contains invalid characters"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerAppIdInvalidCharacterUpperG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0eG"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        None,
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. app_id argument contains invalid characters"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerAppIdInvalidCharacterLowerG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0eg"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. app_id argument contains invalid characters"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerAppIdInvalidCharacterSymbol(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0e;"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. app_id argument contains invalid characters"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerExpiresKeyError(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Missing argument expires"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerExpiresInvalidLength19(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. expires argument invalid length"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerExpiresInvalidLength21(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00ZZ"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. expires argument invalid length"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerExpiresInvalidCharacterFull(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Ａ"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. expires argument contains invalid characters"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerExpiresInvalidCharacterSymbol(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00;"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. expires argument contains invalid characters"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerExpiresInvalidCharacterAlphabet(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00X"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. expires argument contains invalid characters"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerSignatureKeyError(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Missing argument signature"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerSignatureInvalidLength63(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517c"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. signature argument invalid length"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerSignatureInvalidLength65(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cfa"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. signature argument invalid length"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerSignatureInvalidCharacterFull(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cＡ"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. signature argument contains invalid characters"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerSignatureInvalidCharacterUpperG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cG"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. signature argument contains invalid characters"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerSignatureInvalidCharacterLowerG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cg"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. signature argument contains invalid characters"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerSignatureInvalidCharacterSymbol(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517c;"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 403

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid data received. signature argument contains invalid characters"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerSignatureVerifyNG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed1"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    expires = "2100-04-01T00:01:00Z"
    signature = "5f9b5e7b15461e840c3bdcaac91a1964a93466cad743cf2f0bfed1701e91cb7c"
    hashServerSecret = "83acd17b5a6973286057f248a96ce805c5bd74f44f878ba6e369fece6af87d22"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T00:00:30.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.Keys, "app_id", appId), mock.patch.object(dta.Keys, "app_key", appKey), mock.patch.object(dta.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 401

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            assert responseJson["message"] == "Invalid signature"
            assert responseJson["code"] == 401

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ServerSecretHandlerSignatureSecretsError(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    expires = "2100-04-01T00:01:00Z"
    signature = "5f9b5e7b15461e840c3bdcaac91a1964a93466cad743cf2f0bfed1701e91cb7c"
    hashServerSecret = "83acd17b5a6973286057f248a96ce805c5bd74f44f878ba6e369fece6af87d22"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
    }
    url = "{0}/serverSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T00:00:30.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.Keys, "app_id", appId), mock.patch.object(dta.Keys, "app_key", appKey), mock.patch.object(dta.log, "error", mockLog), mocker.patch("dta.secrets.MasterSecret.get_server_secret", side_effect=secrets.SecretsError("error")):
        try:
            response = yield http_client.fetch(request)
            assert False

        except dta.tornado.httpclient.HTTPError as e:
            assert e.code == 500

            assert e.response.headers.get("Access-Control-Allow-Origin") == "*"
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
            assert e.response.headers.get("Content-Type") == "application/json; charset=UTF-8"

            responseJson = json.loads(e.response.body)
            request_info_debug = 'GET /serverSecret 127.0.0.1 %s ' % (userAgent)
            msg = "M-Pin Server Secret Generation Failed: {0}. Request info: {1}".format("error", request_info_debug)
            assert responseJson["reason"] == "M-Pin Server Secret Generation Failed"
            assert responseJson["errorCode"] == "error"

            mockLog.assert_called_with("/serverSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", msg, userAgent).decode("utf-8"))
