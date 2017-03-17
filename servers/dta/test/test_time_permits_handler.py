#coding:utf-8
import datetime
import json
import mock
import os
import pytest
import re
import sys

from tornado.httputil import url_concat

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
def test_TimePermitsHandlerOK(http_client, base_url, mocker):
    appKey = "95735f53a8a7acfb68748c3d47924a4f"
    hashMpinId = "cd4846168f526075b4068da74078c4d8a9e5eeb179148540b3ec7fe1f91a5e95"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    count = "1"
    timePermits = {'47572': '04193b21a33d990c829521c5e89b7924d248de8a8c412e9ab4a33315892670f0bb1d0cf35d31f1a0233466c346a34f8e0687688f399c1870cddaf79820564e9228'}

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
    url_params = url_concat(url, param_values)

    request = dta.tornado.httpclient.HTTPRequest(
        url_params,
        "GET",
        dta.tornado.httputil.HTTPHeaders({"User-Agent": userAgent}),
    )

    mockTime = datetime.datetime.strptime("2100-04-01T12:00:00.000001", "%Y-%m-%dT%H:%M:%S.%f")
    mockLog = mocker.Mock()
    with mocker.patch("dta.Time.syncedNow", return_value=mockTime), mock.patch.object(dta.Keys, "app_key", appKey), mock.patch.object(dta.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == "*"
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control"
        assert response.headers.get("Content-Type") == "application/json; charset=UTF-8"

        responseJson = json.loads(response.body)
        assert responseJson["timePermits"] == timePermits
        assert responseJson["message"] == "OK"

        mockLog.assert_called_with("200 GET /timePermits 127.0.0.1 {0}".format(hashMpinId).decode("utf-8"))

@pytest.mark.gen_test
def test_TimePermitsHandlerUnnessesaryKey(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
        'unnecessaryKey': "test",
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. UNNECESSARYKEY ARGUMENT UNNECESSARY"

@pytest.mark.gen_test
def test_TimePermitsHandlerHashMpinIdKeyError(http_client, base_url, mocker):
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    count = 12345678901234567890

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "MISSING ARGUMENT HASH_MPIN_ID"

@pytest.mark.gen_test
def test_TimePermitsHandlerHashMpinIdInvalidLength63(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f4"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. HASH_MPIN_ID SHOULD BE 64 BYTES"

@pytest.mark.gen_test
def test_TimePermitsHandlerHashMpinIdInvalidLength65(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46a"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. HASH_MPIN_ID SHOULD BE 64 BYTES"

@pytest.mark.gen_test
def test_TimePermitsHandlerHashMpinIdInvalidCharacterFull(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f4Ａ"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. HEX OBJECT COULD BE DECODED"

@pytest.mark.gen_test
def test_TimePermitsHandlerHashMpinIdInvalidCharacterUpperG(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f4G"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. HEX OBJECT COULD BE DECODED"

@pytest.mark.gen_test
def test_TimePermitsHandlerHashMpinIdInvalidCharacterLowerG(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f4g"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. HEX OBJECT COULD BE DECODED"

@pytest.mark.gen_test
def test_TimePermitsHandlerHashMpinIdInvalidCharacterSymbol(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f4;"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. HEX OBJECT COULD BE DECODED"

@pytest.mark.gen_test
def test_TimePermitsHandlerSignatureKeyError(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "MISSING ARGUMENT SIGNATURE"

@pytest.mark.gen_test
def test_TimePermitsHandlerSignatureInvalidLength63(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517c"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. SIGNATURE ARGUMENT INVALID LENGTH"

@pytest.mark.gen_test
def test_TimePermitsHandlerSignatureInvalidLength65(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cfa"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. SIGNATURE ARGUMENT INVALID LENGTH"

@pytest.mark.gen_test
def test_TimePermitsHandlerSignatureInvalidCharacterFull(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cＡ"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. SIGNATURE ARGUMENT CONTAINS INVALID CHARACTERS"

@pytest.mark.gen_test
def test_TimePermitsHandlerSignatureInvalidCharacterUpperG(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cG"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. SIGNATURE ARGUMENT CONTAINS INVALID CHARACTERS"

@pytest.mark.gen_test
def test_TimePermitsHandlerSignatureInvalidCharacterLowerG(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cg"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. SIGNATURE ARGUMENT CONTAINS INVALID CHARACTERS"

@pytest.mark.gen_test
def test_TimePermitsHandlerSignatureInvalidCharacterSymbol(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517c;"
    count = "12345678901234567890"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. SIGNATURE ARGUMENT CONTAINS INVALID CHARACTERS"

@pytest.mark.gen_test
def test_TimePermitsHandlerCountKeyError(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "MISSING ARGUMENT COUNT"

@pytest.mark.gen_test
def test_TimePermitsHandlerCountInvalidCharacterFull(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    count = "1234567890123456789Ａ"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. COUNT ARGUMENT CONTAINS INVALID CHARACTERS"

@pytest.mark.gen_test
def test_TimePermitsHandlerCountInvalidCharacterSymbol(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    count = "1234567890123456789;"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. COUNT ARGUMENT CONTAINS INVALID CHARACTERS"

@pytest.mark.gen_test
def test_TimePermitsHandlerCountInvalidCharacterAlphabet(http_client, base_url, mocker):
    hashMpinId = "9a3e3fd400f9a508652638c47b7b0ac11d7dd015f29a15805300a3b31b035f46"
    signature = "f357c6951ca31142f6a31c426b6fb2d0cb2db55510df930b8ea9e58eff6517cf"
    count = "1234567890123456789a"

    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    param_values = {
        'hash_mpin_id': hashMpinId,
        'signature': signature,
        'count': count,
    }
    url = "{0}/timePermits".format(base_url)
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
            assert responseJson["message"] == "INVALID DATA RECEIVED. COUNT ARGUMENT CONTAINS INVALID CHARACTERS"
