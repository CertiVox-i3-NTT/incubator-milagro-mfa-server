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
def test_ClientSecretHandlerOK(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    expires = "2100-04-01T12:00:00Z"
    signature = "b38b96841d93be411555752da566a110958e9f467060327d36e23d0d1ef5a499"
    hashMpinId = "a43916120cbf6c4777896049add3d19d7b28a7e797272f161045d2024daa9123"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0
    hashClientSecret = "e4fca6cf8e8882863f8be6d65569f35f080d168df79a342c3f5e9be43628f590"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T11:59:30.000001", "%Y-%m-%dT%H:%M:%S.%f")
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
        assert responseJson["clientSecret"] == "04158a3a7b23342be3a00bb686b05b8497f5117f507c9b79e4df48eca9fb0128911215e5742b006e7089419c1fdb0fb8318b2a63d4a3c2ae153a3c6dd3d4d6ed41"
        assert responseJson["message"] == "OK"

        mockLog.assert_called_with("200 GET /clientSecret 127.0.0.1 {0}".format(hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerNoMobile(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    expires = "2100-04-01T12:00:00Z"
    signature = "b38b96841d93be411555752da566a110958e9f467060327d36e23d0d1ef5a499"
    hashMpinId = "a43916120cbf6c4777896049add3d19d7b28a7e797272f161045d2024daa9123"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    hashClientSecret = "e4fca6cf8e8882863f8be6d65569f35f080d168df79a342c3f5e9be43628f590"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
    }
    url = "{0}/clientSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T11:59:30.000001", "%Y-%m-%dT%H:%M:%S.%f")
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
        assert responseJson["clientSecret"] == "04158a3a7b23342be3a00bb686b05b8497f5117f507c9b79e4df48eca9fb0128911215e5742b006e7089419c1fdb0fb8318b2a63d4a3c2ae153a3c6dd3d4d6ed41"
        assert responseJson["message"] == "OK"

        mockLog.assert_called_with("200 GET /clientSecret 127.0.0.1 {0}".format(hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashUserIdValidLength0(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    expires = "2100-04-01T12:00:00Z"
    signature = "3e90ae1d8080340cf85766e230bc1be2773dc664df579e281108f4c4ae781069"
    hashMpinId = "a43916120cbf6c4777896049add3d19d7b28a7e797272f161045d2024daa9123"
    hashUserId = ""
    mobile = 0
    hashClientSecret = "e4fca6cf8e8882863f8be6d65569f35f080d168df79a342c3f5e9be43628f590"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T11:59:30.000001", "%Y-%m-%dT%H:%M:%S.%f")
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
        assert responseJson["clientSecret"] == "04158a3a7b23342be3a00bb686b05b8497f5117f507c9b79e4df48eca9fb0128911215e5742b006e7089419c1fdb0fb8318b2a63d4a3c2ae153a3c6dd3d4d6ed41"
        assert responseJson["message"] == "OK"

        mockLog.assert_called_with("200 GET /clientSecret 127.0.0.1 {0}".format(hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerUnnessesaryKey(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
        'unnecessaryKey': "test",
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Invalid data received. unnecessaryKey argument unnecessary"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format("", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerAppIdKeyError(http_client, base_url, mocker):
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format("", "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerAppIdInvalidCharacterFull(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0Ａ"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerAppIdInvalidCharacterUpperG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0eG"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], "unknown").decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerAppIdInvalidCharacterLowerG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0eg"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerAppIdInvalidCharacterSymbol(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0e;"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerExpiresKeyError(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerExpiresInvalidLength19(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerExpiresInvalidLength21(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00ZZ"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerExpiresInvalidCharacterFull(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Ａ"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerExpiresInvalidCharacterSymbol(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00;"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerExpiresInvalidCharacterAlphabet(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00X"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerSignatureKeyError(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerSignatureInvalidLength63(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517c"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerSignatureInvalidLength65(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cfa"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerSignatureInvalidCharacterFull(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cＡ"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerSignatureInvalidCharacterUpperG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cG"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerSignatureInvalidCharacterLowerG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cg"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerSignatureInvalidCharacterSymbol(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517c;"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashMpinIdKeyError(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Missing argument hash_mpin_id"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, "", responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashMpinIdInvalidLength63(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f4"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Invalid data received. hash_mpin_id should be 64 bytes"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashMpinIdInvalidLength65(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46a"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Invalid data received. hash_mpin_id should be 64 bytes"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashMpinIdInvalidCharacterFull(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f4Ａ"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Invalid data received. Hex object could be decoded"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashMpinIdInvalidCharacterUpperG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f4G"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Invalid data received. Hex object could be decoded"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashMpinIdInvalidCharacterLowerG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f4g"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Invalid data received. Hex object could be decoded"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashMpinIdInvalidCharacterSymbol(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f4;"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Invalid data received. Hex object could be decoded"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashUserIdKeyError(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Missing argument hash_user_id"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashUserIdInvalidLength63(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4a"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Invalid data received. hash_user_id argument invalid length"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashUserIdInvalidLength65(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4afa"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Invalid data received. hash_user_id argument invalid length"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashUserIdInvalidCharacterFull(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4aＡ"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Invalid data received. hash_user_id argument contains invalid characters"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashUserIdInvalidCharacterUpperG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4aG"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Invalid data received. hash_user_id argument contains invalid characters"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashUserIdInvalidCharacterLowerG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4ag"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Invalid data received. hash_user_id argument contains invalid characters"
            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerHashUserIdInvalidCharacterSymbol(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    expires = "2100-04-01T12:00:00Z"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4a;"
    mobile = 0

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
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
            assert responseJson["message"] == "Invalid data received. hash_user_id argument contains invalid characters"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerSignatureVerifyNG(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed1"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    expires = "2100-04-01T12:00:00Z"
    signature = "b38b96841d93be411555752da566a110958e9f467060327d36e23d0d1ef5a499"
    hashMpinId = "a43916120cbf6c4777896049add3d19d7b28a7e797272f161045d2024daa9123"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0
    hashClientSecret = "e4fca6cf8e8882863f8be6d65569f35f080d168df79a342c3f5e9be43628f590"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T11:59:30.000001", "%Y-%m-%dT%H:%M:%S.%f")
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

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_ClientSecretHandlerSecretsError(http_client, base_url, mocker):
    appId = "828aab3a428811e6b23b06df5546c0ed"
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    expires = "2100-04-01T12:00:00Z"
    signature = "b38b96841d93be411555752da566a110958e9f467060327d36e23d0d1ef5a499"
    hashMpinId = "a43916120cbf6c4777896049add3d19d7b28a7e797272f161045d2024daa9123"
    hashUserId = "cd9388268f58c5b0b78eaf66aa97c85f3f954e5fb516fa869cbd26f5f48ff4af"
    mobile = 0
    hashClientSecret = "e4fca6cf8e8882863f8be6d65569f35f080d168df79a342c3f5e9be43628f590"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'app_id': appId,
        'expires': expires,
        'signature': signature,
        'hash_mpin_id': hashMpinId,
        'hash_user_id': hashUserId,
        'mobile': mobile,
    }
    url = "{0}/clientSecret".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T11:59:30.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.Keys, "app_id", appId), mock.patch.object(dta.Keys, "app_key", appKey), mock.patch.object(dta.log, "error", mockLog), mock.patch("dta.secrets.MasterSecret.get_client_secret", side_effect=secrets.SecretsError("error")):
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
            assert responseJson["errorCode"] == "error"
            assert responseJson["message"] == "M-Pin Client Secret Generation Failed"

            mockLog.assert_called_with("/clientSecret 127.0.0.1 {0} {1} {2} {3}".format(appId, hashMpinId, responseJson["message"], userAgent).decode("utf-8"))
