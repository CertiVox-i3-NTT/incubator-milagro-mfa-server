#coding:utf-8
import datetime
import json
import mock
import os
import pytest
import re
import sys
import urllib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR + '/..')

import rps

http_server = None

@pytest.fixture
def app(httpserver):
    rps.options.parse_config_file(rps.options.configFile)

    # Set Log level
    #rps.log.setLevel(rps.getLogLevel(rps.options.logLevel))
    #rps.log.setLevel("DEBUG")

    #rps.detectProxy()

    # Load the credentials from file
    rps.credentialsFile = rps.options.credentialsFile
    rps.Keys.loadFromFile(rps.credentialsFile)

    # TMP fix for 'ValueError: I/O operation on closed epoll fd'
    # Fixed in Tornado 4.2
    rps.tornado.ioloop.IOLoop.instance()

    # Sync time to CertiVox time server
    mockResponse = {"Fallback": False, "Format": "u", "Epoch": "1459436400.000", "Time": "2016-04-01 00:00:00Z"}
    httpserver.serve_content(json.dumps(mockResponse), 200)
    with mock.patch("rps.Keys.timeServer", return_value="{0}/".format(httpserver.url)):
        if rps.options.syncTime:
            rps.Time.getTime(wait=True)

    #rps.Keys.getAPISettings(wait=True)
    rps.Keys.timePermitsStorageURL = "https://timepermits.certivox.net"

    '''
    appId : 828aab3a428811e6b23b06df5546c0ed
    appKey : 95735f53a8a7acfb68748c3d47924a4f
    salt :
    DTA Backup Server Key :

    '''

    with mock.patch.object(rps.options.mockable(), "EntropySources", "dev_urandom:100".decode("utf-8")), mock.patch("rps.secrets.ServerSecret._get_server_secret", return_value="019449d771da50bb07d52426d55cbb5a83a0e905e78070bf447930735f5b91681d58c999ddd965fd48f5843742f0d91b3884b3a06577e63052d9d93145c026fa1781eedd973d15838188b3eb8ea82e3b5144465d05797790df6658756cc33dcb1799188be80b52b7ac1546725e6401c6730746987865eea9ba1c9bf34aab3e02".decode("hex")):
        global http_server
        http_server = rps.Application()

        return http_server

@pytest.mark.gen_test
def test_RPSAccessNumberHandler(http_client, base_url, mocker):
    baseURL = "/rps"
    webOTT = "26fc14be05fa66ad440a4ca627075540"
    wId = "5319366"
    authOTT = "aaaa"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030393a31323a30352e353733393631222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226237336338303635646632656335323135373266303235656332363638326430227d"
    authToken = {
        "mpin_id": mpinId.decode("hex"),
        "mpin_id_hex": mpinId,
        "successCode": 0,
        "pinError": 0,
        "pinErrorCost": 0,
        "expires": "2100-04-01T12:00:00Z",
        "WID": wId,
        "OTP": "0"
    }
    userId = "root@localhost"

    body = {
        "webOTT": webOTT
    }
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/access".format(base_url, baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", webOTT=webOTT, wid=wId, authOTT=authOTT, mpinid=mpinId.decode("hex"), authToken=authToken, status=200)
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        responseJson = json.loads(response.body)
        assert responseJson["userId"] == userId
        assert responseJson["authOTT"] == authOTT

        mockLog.assert_called_with("200 POST {0}/access 127.0.0.1 {1} {2} {3} {4}".format(baseURL, xForwardedFor, "", userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAccessNumberHandlerCapital(http_client, base_url, mocker):
    baseURL = "/rps"
    webOTT = "26Fc14be05fa66Ad440a4ca627075540"
    wId = "5319366"
    authOTT = "aaaa"
    mpinId = "7b226d6f62696c65223a20302c2022697373756564223a2022323031362d30372d32392030393a31323a30352e353733393631222c2022757365724944223a2022726f6f74406c6f63616c686f7374222c202273616c74223a20226237336338303635646632656335323135373266303235656332363638326430227d"
    authToken = {
        "mpin_id": mpinId.decode("hex"),
        "mpin_id_hex": mpinId,
        "successCode": 0,
        "pinError": 0,
        "pinErrorCost": 0,
        "expires": "2100-04-01T12:00:00Z",
        "WID": wId,
        "OTP": "0"
    }
    userId = "root@localhost"

    body = {
        "webOTT": webOTT
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/access".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", webOTT=webOTT, wid=wId, authOTT=authOTT, mpinid=mpinId.decode("hex"), authToken=authToken, status=200)
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        responseJson = json.loads(response.body)
        print responseJson
        assert responseJson["userId"] == userId
        assert responseJson["authOTT"] == authOTT

        mockLog.assert_called_with("200 POST {0}/access 127.0.0.1  {1} {2} {3}".format(baseURL, "", userId, "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAccessNumberHandlerUnnecessaryKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    webOTT = "9f86d081884c7d659a2feaa0c55ad015"
    body = {
        "unnecessaryKey":"test",
        "webOTT": webOTT
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/access".format(base_url,baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/access 127.0.0.1 {1} {2} {3} {4} Invalid data received. unnecessaryKey argument unnecessary {5}".format(baseURL, xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAccessNumberHandlerWebOTTKeyError(http_client, base_url, mocker):
    baseURL = "/rps"
    webOTT = "9f86d081884c7d659a2feaa0c55ad015"
    body = {
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/access".format(base_url,baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/access 127.0.0.1  {1} {2} {3} Invalid data received. webOTT argument missing unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAccessNumberHandlerWebOTTInvalidLength33Error(http_client, base_url, mocker):
    baseURL = "/rps"
    webOTT = "9f86d081884c7d659a2feaa0c55ad015f"
    body = {
        "webOTT": webOTT
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/access".format(base_url,baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400
            print e.message
            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/access 127.0.0.1  {1} {2} {3} Invalid data received. webOTT argument invalid length unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAccessNumberHandlerWebOTTInvalidLength31Error(http_client, base_url, mocker):
    baseURL = "/rps"
    webOTT = "9f86d081884c7d659a2feaa0c55ad01"
    body = {
        "webOTT": webOTT
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/access".format(base_url,baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/access 127.0.0.1 {1} {2} {3} {4} Invalid data received. webOTT argument invalid length {5}".format(baseURL, xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAccessNumberHandlerWebOTTInvalidCharacterFullError(http_client, base_url, mocker):
    baseURL = "/rps"
    webOTT = "9f86d081884c7d659a2feaa0c55ad01Ａ"
    body = {
        "webOTT": webOTT
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/access".format(base_url,baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/access 127.0.0.1  {1} {2} {3} Invalid data received. webOTT argument contains invalid characters unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAccessNumberHandlerWebOTTInvalidCharacterNotHexError(http_client, base_url, mocker):
    baseURL = "/rps"
    webOTT = "9f86d081884c7d659a2feaa0c55ad01g"
    body = {
        "webOTT": webOTT
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/access".format(base_url,baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/access 127.0.0.1  {1} {2} {3} Invalid data received. webOTT argument contains invalid characters unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAccessNumberHandlerWebOTTInvalidCharacterNotHexCapitalError(http_client, base_url, mocker):
    baseURL = "/rps"
    webOTT = "9f86d081884c7d659a2feaa0c55ad01G"
    body = {
        "webOTT": webOTT
    }
    userAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"
    xForwardedFor = "127.0.0.1"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/access".format(base_url,baseURL),
        "POST",
        rps.tornado.httputil.HTTPHeaders({"User-Agent": userAgent, "X-Forwarded-For": xForwardedFor}),
        json.dumps(body)
    )

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/access 127.0.0.1 {1} {2} {3} {4} Invalid data received. webOTT argument contains invalid characters {5}".format(baseURL, xForwardedFor, "", "", "", userAgent).decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAccessNumberHandlerWebOTTInvalidCharacterSymbolsError(http_client, base_url, mocker):
    baseURL = "/rps"
    webOTT = "9f86d081884c7d659a2feaa0c55ad01/"
    body = {
        "webOTT": webOTT
    }

    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/access".format(base_url,baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/access 127.0.0.1  {1} {2} {3} Invalid data received. webOTT argument contains invalid characters unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAccessNumberHandlerValueError(http_client, base_url, mocker):
    baseURL = "/rps"
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/access".format(base_url,baseURL),
        "POST",
        None,
        "jsonError"
    )

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/access 127.0.0.1  {1} {2} {3} Cannot decode body as JSON. unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAccessNumberHandlerJsonError(http_client, base_url, mocker):
    baseURL = "/rps"
    body = {
        "webOTT": 12
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/access".format(base_url,baseURL),
        "POST",
        None,
        json.dumps(body)
    )

    mockLog = mocker.Mock()
    with mock.patch.object(rps.log, "error", mockLog):
        try:
            response = yield http_client.fetch(request)
            assert False
        except rps.tornado.httpclient.HTTPError as e:
            assert e.code == 400

            assert e.response.headers.get("Access-Control-Allow-Origin") == None
            assert e.response.headers.get("Access-Control-Allow-Credentials") == "true"
            assert e.response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
            assert e.response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

            mockLog.assert_called_with("{0}/access 127.0.0.1  {1} {2} {3} Cannot decode body as JSON. unknown".format(baseURL, "", "", "").decode("utf-8"))

@pytest.mark.gen_test
def test_RPSAccessNumberHandlerNoMpinID(http_client, base_url, mocker):
    baseURL = "/rps"
    webOTT = "26fc14be05fa66ad440a4ca627075540"
    wId = "5319366"
    authOTT = "aaaa"
    authToken = {
        "mpin_id": "",
        "mpin_id_hex": "",
        "successCode": 0,
        "pinError": 0,
        "pinErrorCost": 0,
        "expires": "2100-04-01T12:00:00Z",
        "WID": wId,
        "OTP": "0"
    }

    body = {
        "webOTT": webOTT
    }
    request = rps.tornado.httpclient.HTTPRequest(
        "{0}{1}/access".format(base_url, baseURL),
        "POST",
        None,
        json.dumps(body)
    )
    mockLog = mocker.Mock()
    http_server.storage.add(stage="auth", expire_time="2100-04-01T12:00:00", webOTT=webOTT, wid=wId, authOTT=authOTT, authToken=authToken, status=200)
    with mock.patch.object(rps.log, "info", mockLog):
        response = yield http_client.fetch(request)

        assert response.code == 200

        assert response.headers.get("Access-Control-Allow-Origin") == None
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        assert response.headers.get("Access-Control-Allow-Methods") == "GET,PUT,POST,DELETE,OPTIONS"
        assert response.headers.get("Access-Control-Allow-Headers") == "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate"

        responseJson = json.loads(response.body)
        print responseJson
        assert responseJson["userId"] == ""
        assert responseJson["authOTT"] == authOTT

        mockLog.assert_called_with("200 POST {0}/access 127.0.0.1  {1} {2} {3}".format(baseURL, "", "", "").decode("utf-8"))
